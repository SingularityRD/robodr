//! [`ConsistencyMonitor`]: the stateful detector.
//!
//! Per-event path (`on_command`, `on_feedback`, `tick`, `set_safety_stop`)
//! performs **no heap allocation** and is deterministic: all state lives in
//! fixed-size arrays plus one ring buffer allocated in [`ConsistencyMonitor::new`].
//! Findings are handed to a caller-supplied sink as plain `Copy` values;
//! turning one into a [`Deviation`] (which owns a `String`) is the caller's
//! choice and happens off the per-sample path.
//!
//! Feedback state is kept per **(source type, publisher)** in a fixed table
//! of [`PUBLISHER_SLOTS`] slots per source type, keyed by the full
//! [`PublisherKey`] (16-byte GUID or caller id, compared exactly), so a
//! second publisher on the same topic cannot reset or dilute the real
//! publisher's detector state. Publishers beyond the table share one
//! dedicated **overflow** slot per source type (never a real publisher's),
//! and the overflow itself is a finding.

use crate::config::{ConfigError, MonitorConfig, Persistence};
use crate::model::{first_order_step, CmdRec, CommandRing};
use crate::sample::{Axis, CommandSample, FeedbackSample, FeedbackSource, PublisherKey};
use robodr_events::{Deviation, Severity};
use serde::{Deserialize, Serialize};

/// Stable rule ids.
pub mod rules {
    /// Sustained gap between the command model and measured feedback.
    pub const FEEDBACK_DIVERGENCE: &str = "robot.motion.feedback_divergence";
    /// Measured motion while the observed command is rest / absent.
    pub const UNCOMMANDED_MOTION: &str = "robot.motion.uncommanded_motion";
    /// Feedback frozen, silent, or with anomalous timestamps.
    pub const FROZEN_FEEDBACK: &str = "robot.motion.frozen_feedback";
    /// Two independent feedback sources persistently disagree.
    pub const CROSS_SENSOR_DISAGREEMENT: &str = "robot.motion.cross_sensor_disagreement";
    /// Feedback carried NaN / infinity.
    pub const INVALID_FEEDBACK: &str = "robot.motion.invalid_feedback";
    /// More than one publisher interleaves samples for the same feedback
    /// source type.
    pub const MULTIPLE_FEEDBACK_PUBLISHERS: &str = "robot.motion.multiple_feedback_publishers";
    /// One feedback stream repeatedly jumps between values faster than the
    /// platform can accelerate: two streams interleaved under one
    /// (unattributed) publisher identity, or a corrupted driver.
    pub const INCONSISTENT_FEEDBACK_STREAM: &str = "robot.motion.inconsistent_feedback_stream";
}

/// Distinct publishers tracked per feedback source type. Further publishers
/// share a dedicated overflow slot of that source type (never a tracked
/// publisher's slot), are counted in [`MonitorStats::publisher_overflow`]
/// and flagged once ([`Evidence::PublisherOverflow`]).
pub const PUBLISHER_SLOTS: usize = 4;

const N_SRC: usize = 5;
const N_AXIS: usize = 3;
/// State entities per source type: the tracked slots plus the overflow slot.
const ENT_PER_SRC: usize = PUBLISHER_SLOTS + 1;
const OVERFLOW_SLOT: usize = PUBLISHER_SLOTS;
const N_ENT: usize = N_SRC * ENT_PER_SRC;
const N_EPAIR: usize = N_ENT * (N_ENT - 1) / 2;
const NS_PER_S: f64 = 1e9;

/// Which way feedback left the expected band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Moving less than commanded (stall, obstruction, undeclared e-stop,
    /// telemetry hiding motion that is commanded).
    Under,
    /// Moving more than commanded.
    Over,
    /// Moving the other way.
    Opposite,
}

/// Kind of timestamp anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StampAnomaly {
    /// Stamp earlier than the previous one from the same source (replay loop
    /// restart, interleaved second publisher).
    Backwards,
    /// Stamp identical to the previous one (replayed / re-published message).
    Duplicate,
    /// Stamp ahead of the observer clock beyond `max_future_skew_ns`.
    Future,
    /// Stamp older than `max_stamp_age_ns` on arrival (replay with original
    /// stamps, or a badly stalled pipeline).
    Late,
}

impl StampAnomaly {
    const fn index(self) -> usize {
        match self {
            StampAnomaly::Backwards => 0,
            StampAnomaly::Duplicate => 1,
            StampAnomaly::Future => 2,
            StampAnomaly::Late => 3,
        }
    }
    const fn as_str(self) -> &'static str {
        match self {
            StampAnomaly::Backwards => "backwards",
            StampAnomaly::Duplicate => "duplicate",
            StampAnomaly::Future => "from the future",
            StampAnomaly::Late => "late",
        }
    }
}

/// Structured evidence for a finding. Every variant is `Copy` and
/// allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FeedbackDivergence {
        source: FeedbackSource,
        axis: Axis,
        direction: Direction,
        /// Command in effect after the minimum latency.
        commanded: Option<f64>,
        expected_lo: f64,
        expected_hi: f64,
        tolerance: f64,
        measured: f64,
        since_ns: u64,
        samples: u32,
    },
    UncommandedMotion {
        source: FeedbackSource,
        axis: Axis,
        measured: f64,
        /// Largest |expected| from the decaying model (coast-down allowance).
        expected_abs_max: f64,
        tolerance: f64,
        since_ns: u64,
        samples: u32,
    },
    FrozenValues {
        source: FeedbackSource,
        /// Consecutive bit-identical samples while commanded to move.
        repeats: u32,
        since_ns: u64,
    },
    StaleFeedback {
        source: FeedbackSource,
        last_rx_ns: u64,
        age_ns: u64,
    },
    TimestampAnomaly {
        source: FeedbackSource,
        anomaly: StampAnomaly,
        stamp_ns: u64,
        prev_stamp_ns: Option<u64>,
        now_ns: u64,
    },
    NonFiniteFeedback {
        source: FeedbackSource,
        axis: Axis,
    },
    /// Sustained rate of non-finite values while motion is expected or
    /// observed (NaN used to blind the detector).
    NonFiniteRate {
        source: FeedbackSource,
        axis: Axis,
        /// Non-finite samples in the window.
        invalid: u32,
        /// Window size (samples, at most 64).
        window: u32,
    },
    /// A publisher resumed after another one published for the same source
    /// type: two concurrent publishers.
    MultiplePublishers {
        source: FeedbackSource,
        publisher: PublisherKey,
        other: PublisherKey,
        /// Publishers active within `publisher_expiry_ns`.
        active: u32,
    },
    /// More than [`PUBLISHER_SLOTS`] publishers active on one source type:
    /// the extra ones share the overflow slot (flood / GUID churn).
    PublisherOverflow {
        source: FeedbackSource,
        /// The publisher that did not get a slot of its own.
        publisher: PublisherKey,
        /// Tracked slots per source type ([`PUBLISHER_SLOTS`]).
        slots: u32,
    },
    /// Repeated physically implausible jumps within one (source, publisher)
    /// stream.
    InconsistentStream {
        source: FeedbackSource,
        axis: Axis,
        /// Implausible jumps in the episode so far.
        jumps: u32,
        /// The jump that fired: previous and current value.
        from: f64,
        to: f64,
        /// |to - from| / dt, units/s^2.
        implied_rate: f64,
        since_ns: u64,
    },
    CrossSensorDisagreement {
        axis: Axis,
        source_a: FeedbackSource,
        value_a: f64,
        source_b: FeedbackSource,
        value_b: f64,
        tolerance: f64,
        /// The source with the higher `trust_rank`, if they differ: the side
        /// more likely to be telling the truth.
        more_trusted: Option<FeedbackSource>,
        since_ns: u64,
        samples: u32,
    },
}

/// One detection: a stable rule id, a severity, when it fired (observer
/// clock) and the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub t_ns: u64,
    pub evidence: Evidence,
    /// Publisher of the feedback sample that triggered the finding, if it
    /// came from one ([`PublisherKey::UNKNOWN`] when the caller used
    /// [`ConsistencyMonitor::on_feedback`]).
    pub publisher: Option<PublisherKey>,
}

impl Finding {
    /// Human-readable one-liner. Allocates.
    pub fn detail(&self) -> String {
        fn ms(ns: u64) -> u64 {
            ns / 1_000_000
        }
        let age = |since: u64| ms(self.t_ns.saturating_sub(since));
        let mut s = self.detail_core(age, ms);
        if let Some(p) = self.publisher {
            if p != PublisherKey::UNKNOWN {
                s.push_str(&format!(" [publisher {p}]"));
            }
        }
        s
    }

    fn detail_core(&self, age: impl Fn(u64) -> u64, ms: fn(u64) -> u64) -> String {
        match self.evidence {
            Evidence::FeedbackDivergence {
                source,
                axis,
                direction,
                commanded,
                expected_lo,
                expected_hi,
                tolerance,
                measured,
                since_ns,
                samples,
            } => {
                let what = match direction {
                    Direction::Under => "robot moving less than commanded",
                    Direction::Over => "robot moving more than commanded",
                    Direction::Opposite => "robot moving opposite to command",
                };
                let cmd = match commanded {
                    Some(c) => format!("{c:.3}"),
                    None => String::from("unspecified"),
                };
                format!(
                    "{} {} feedback {:.3} {} outside expected [{:.3}, {:.3}] +/-{:.3} \
                     (command {}) for {} ms / {} samples: {}",
                    source.as_str(),
                    axis.as_str(),
                    measured,
                    axis.unit(),
                    expected_lo,
                    expected_hi,
                    tolerance,
                    cmd,
                    age(since_ns),
                    samples,
                    what
                )
            }
            Evidence::UncommandedMotion {
                source,
                axis,
                measured,
                expected_abs_max,
                tolerance,
                since_ns,
                samples,
            } => format!(
                "{} reports {} motion {:.3} {} with no motion commanded on the observed \
                 channel (allowance {:.3}+{:.3}) for {} ms / {} samples: command \
                 bypassing the observed channel, or mechanical",
                source.as_str(),
                axis.as_str(),
                measured,
                axis.unit(),
                expected_abs_max,
                tolerance,
                age(since_ns),
                samples
            ),
            Evidence::FrozenValues {
                source,
                repeats,
                since_ns,
            } => format!(
                "{} feedback bit-identical for {} samples / {} ms while commanded to move: \
                 frozen or replayed telemetry",
                source.as_str(),
                repeats,
                age(since_ns)
            ),
            Evidence::StaleFeedback {
                source,
                last_rx_ns: _,
                age_ns,
            } => format!(
                "{} feedback silent for {} ms while commanded to move",
                source.as_str(),
                ms(age_ns)
            ),
            Evidence::TimestampAnomaly {
                source,
                anomaly,
                stamp_ns,
                prev_stamp_ns,
                now_ns,
            } => {
                let prev = match prev_stamp_ns {
                    Some(p) => format!("{p}"),
                    None => String::from("none"),
                };
                format!(
                    "{} feedback stamp {} {} (previous {}, observer clock {}): \
                     possible replayed or injected telemetry",
                    source.as_str(),
                    stamp_ns,
                    anomaly.as_str(),
                    prev,
                    now_ns
                )
            }
            Evidence::NonFiniteFeedback { source, axis } => format!(
                "{} {} feedback is NaN or infinite",
                source.as_str(),
                axis.as_str()
            ),
            Evidence::NonFiniteRate {
                source,
                axis,
                invalid,
                window,
            } => format!(
                "{} {} feedback NaN/infinite in {} of the last {} samples while the robot \
                 is moving or should be: invalid values blinding motion checks",
                source.as_str(),
                axis.as_str(),
                invalid,
                window
            ),
            Evidence::MultiplePublishers {
                source,
                publisher,
                other,
                active,
            } => format!(
                "{} feedback from {} interleaved publishers (publisher {} resumed after \
                 {}): possible injected second publisher",
                source.as_str(),
                active,
                publisher,
                other
            ),
            Evidence::PublisherOverflow {
                source,
                publisher,
                slots,
            } => format!(
                "{} feedback from more than {} concurrent publishers (publisher {} has no slot \
                 of its own): publisher flood or GUID churn, possible injection",
                source.as_str(),
                slots,
                publisher
            ),
            Evidence::InconsistentStream {
                source,
                axis,
                jumps,
                from,
                to,
                implied_rate,
                since_ns,
            } => format!(
                "{} {} feedback jumped implausibly {} times in {} ms (last {:.3} -> {:.3} {}, \
                 implied {:.1} {}/s): two interleaved publishers on one stream, or corrupted \
                 telemetry",
                source.as_str(),
                axis.as_str(),
                jumps,
                age(since_ns),
                from,
                to,
                axis.unit(),
                implied_rate,
                axis.unit()
            ),
            Evidence::CrossSensorDisagreement {
                axis,
                source_a,
                value_a,
                source_b,
                value_b,
                tolerance,
                more_trusted,
                since_ns,
                samples,
            } => {
                let trust = match more_trusted {
                    Some(s) => format!("; {} is the more trusted source", s.as_str()),
                    None => String::new(),
                };
                format!(
                    "{} {} {:.3} vs {} {:.3} {} disagree beyond {:.3} for {} ms / {} samples{}",
                    source_a.as_str(),
                    axis.as_str(),
                    value_a,
                    source_b.as_str(),
                    value_b,
                    axis.unit(),
                    tolerance,
                    age(since_ns),
                    samples,
                    trust
                )
            }
        }
    }

    /// Convert to the shared deviation type. Allocates (the detail string).
    pub fn to_deviation(&self) -> Deviation {
        Deviation::new(self.rule, self.severity, self.detail())
    }
}

/// Counters for observability and tuning. All saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorStats {
    pub commands: u64,
    /// Commands on channels not in `command_channels`.
    pub commands_ignored: u64,
    /// Non-finite command axis values (treated as 0 = "nothing valid commanded").
    pub invalid_command_values: u64,
    pub feedback: u64,
    /// Duplicate-stamp feedback dropped from value checks.
    pub duplicates_skipped: u64,
    /// Events whose observer time went backwards (clamped forward).
    pub clock_regressions: u64,
    /// Commands evicted while still inside the latency window: increase
    /// `command_capacity`.
    pub history_underruns: u64,
    pub findings: u64,
    /// Non-finite feedback values (dropped).
    pub invalid_feedback_values: u64,
    /// Feedback from a publisher beyond [`PUBLISHER_SLOTS`] for its source
    /// type (shares that source type's overflow slot).
    pub publisher_overflow: u64,
}

/// Episode-based persistence (see [`Persistence`]): an episode starts at
/// the first bad sample and ends after `clear_samples` consecutive good
/// ones; interleaved good samples only dilute the bad fraction.
///
/// With a non-zero **hold** (`MonitorConfig::episode_hold_ns`), a good
/// sample that arrives within the hold of the latest bad sample of an open
/// episode is *neutral*: it neither dilutes the fraction nor counts toward
/// `clear_samples`. The episode is then judged on the stream's upper
/// envelope (the worst sample of every hold window) rather than on the
/// per-sample majority, so an injector cannot hide a real excursion by
/// interleaving any number of plausible values between real samples (it
/// would have to stop the real samples for longer than the hold). Neutral
/// samples never count as bad, so the hold cannot turn sparse honest
/// outliers into a finding: `min_samples` still counts genuinely bad
/// samples only.
///
/// For the uncommanded and divergence rules (divergence: opposite-direction
/// samples only) the episode also counts its samples at or above
/// a **critical level**: it reports `Critical` once `min_samples` of them
/// were seen, and a latched non-critical episode is **escalated** (fires a
/// second time, once) when that count is reached later. An injector cannot
/// pre-open a `High` episode with mildly bad values and keep it latched to
/// mask later critical motion.
#[derive(Debug, Clone, Copy, Default)]
struct Persist {
    since: Option<u64>,
    bad: u32,
    total: u32,
    good_run: u32,
    fired: bool,
    /// Observer time until which good samples are neutral.
    hold_until: u64,
    /// Largest magnitude among the episode's bad samples.
    peak: f64,
    /// Bad samples at or above the critical level.
    crit: u32,
    /// A critical firing was reported in this episode.
    crit_fired: bool,
}

/// A persistence rule firing.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Fire {
    since: u64,
    /// Bad samples in the episode.
    bad: u32,
    /// Largest |value| among them.
    peak: f64,
    /// At least `min_samples` bad samples reached the critical level.
    critical: bool,
}

impl Persist {
    /// Feed one observation without a hold or critical level (unit tests).
    /// Returns `Some((since, bad_samples))` exactly once per episode, when
    /// the condition first satisfies the rule.
    #[cfg(test)]
    fn observe(&mut self, bad: bool, now: u64, p: &Persistence) -> Option<(u64, u32)> {
        self.observe_held(bad, 0.0, f64::INFINITY, now, 0, p)
            .map(|f| (f.since, f.bad))
    }

    /// Feed one observation of magnitude `mag`, with critical level
    /// `crit_level` (`INFINITY` = none) and hold `hold_ns` (0 = none).
    /// Fires once per episode when the rule is first satisfied, and once
    /// more if a non-critical firing later becomes critical.
    fn observe_held(
        &mut self,
        bad: bool,
        mag: f64,
        crit_level: f64,
        now: u64,
        hold_ns: u64,
        p: &Persistence,
    ) -> Option<Fire> {
        if bad {
            self.good_run = 0;
            self.hold_until = now.saturating_add(hold_ns);
            let since = match self.since {
                Some(s) => s,
                None => {
                    self.bad = 0;
                    self.total = 0;
                    self.peak = 0.0;
                    self.crit = 0;
                    self.crit_fired = false;
                    self.since = Some(now);
                    now
                }
            };
            // `mag` is finite (sanitised feedback); `max` ignores NaN anyway.
            let mag = mag.abs();
            self.peak = self.peak.max(mag);
            if mag >= crit_level {
                self.crit = self.crit.saturating_add(1);
            }
            self.bad = self.bad.saturating_add(1);
            self.total = self.total.saturating_add(1);
            let critical = self.crit >= p.min_samples;
            let fire = |st: &mut Self| {
                st.fired = true;
                st.crit_fired |= critical;
                Some(Fire {
                    since,
                    bad: st.bad,
                    peak: st.peak,
                    critical,
                })
            };
            if !self.fired {
                if self.bad >= p.min_samples
                    && now.saturating_sub(since) >= p.min_duration_ns
                    && f64::from(self.bad) >= p.min_bad_fraction * f64::from(self.total)
                {
                    return fire(self);
                }
            } else if critical && !self.crit_fired {
                return fire(self);
            }
        } else if hold_ns > 0 && self.since.is_some() && now <= self.hold_until {
            // Neutral: within the hold of a bad sample.
        } else {
            self.good_run = self.good_run.saturating_add(1);
            if self.since.is_some() {
                self.total = self.total.saturating_add(1);
            }
            if self.good_run >= p.clear_samples {
                self.since = None;
                self.bad = 0;
                self.total = 0;
                self.fired = false;
            }
        }
        None
    }

    /// Record that the latest firing was reported as critical by the caller
    /// (a per-sample criterion), so no second escalation follows.
    fn mark_critical(&mut self) {
        self.crit_fired = true;
    }

    /// End the episode without counting a good sample (no basis to judge:
    /// warm-up, settling, stale partner). A latched finding stays latched.
    fn interrupt(&mut self) {
        self.since = None;
        self.bad = 0;
        self.total = 0;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Latch {
    latched: bool,
    clean: u32,
}

impl Latch {
    fn trip(&mut self) -> bool {
        self.clean = 0;
        if self.latched {
            false
        } else {
            self.latched = true;
            true
        }
    }
    fn ok(&mut self, rearm: u32) {
        if self.latched {
            self.clean = self.clean.saturating_add(1);
            if self.clean >= rearm {
                self.latched = false;
                self.clean = 0;
            }
        }
    }
}

/// Per source type, across publishers (staleness, publisher interleaving).
#[derive(Debug, Clone, Copy, Default)]
struct SourceAgg {
    seen: bool,
    last_rx: u64,
    reported: [bool; N_AXIS],
    stale_latched: bool,
    last_pub: Option<PublisherKey>,
    multi_latched: bool,
    multi_clean: u32,
    /// An overflow finding was reported; re-armed once the overflow slot
    /// has been silent for `publisher_expiry_ns`.
    overflow_latched: bool,
}

/// Per (source type, publisher) slot.
#[derive(Debug, Clone, Copy, Default)]
struct EntityState {
    publisher: Option<PublisherKey>,
    seen: bool,
    last_rx: u64,
    last_stamp: Option<u64>,
    /// Latest finite value per axis (normalised) and when it was received.
    last_val: [Option<(f64, u64)>; N_AXIS],
    /// Bit patterns of the previous all-finite sample's raw values.
    prev_bits: Option<[Option<u64>; N_AXIS]>,
    frozen_count: u32,
    frozen_since: u64,
    frozen_latched: bool,
    /// Range `(min, max)` of the expected-band midpoint per axis over the
    /// current frozen run: a run only fires once the expectation moved by
    /// at least `frozen_change_factor * abs_tol` on some axis.
    frozen_mid: [Option<(f64, f64)>; N_AXIS],
    stamp_latch: [Latch; 4],
    nonfinite_latch: [Latch; N_AXIS],
    /// Last 64 samples per axis, bit set = non-finite.
    nan_hist: [u64; N_AXIS],
    nan_n: [u8; N_AXIS],
    nan_rate_latched: [bool; N_AXIS],
    /// Previous finite value per axis (normalised), its stamp and arrival.
    prev_fin: [Option<(f64, u64, u64)>; N_AXIS],
    jump: [JumpEpisode; N_AXIS],
}

/// Implausible-jump episode: ends after `jump_window_ns` without a jump
/// (time-based, so interleaved good samples cannot end it).
#[derive(Debug, Clone, Copy, Default)]
struct JumpEpisode {
    since: u64,
    last: Option<u64>,
    count: u32,
    fired: bool,
}

/// The model is run twice, at the two ends of the latency window; the
/// expected band is the hull of the two.
#[derive(Debug, Clone, Copy)]
struct Variant {
    latency_ns: u64,
    e: [Option<f64>; N_AXIS],
}

/// Motion/feedback consistency monitor for one robot. See the crate docs.
#[derive(Debug, Clone)]
pub struct ConsistencyMonitor {
    cfg: MonitorConfig,
    ring: CommandRing,
    variants: [Variant; 2],
    model_t: Option<u64>,
    warmup_until: u64,
    suppress_until: [u64; N_AXIS],
    stop_active: bool,
    stop_changed_at: Option<u64>,
    agg: [SourceAgg; N_SRC],
    /// Indexed by entity `source * (PUBLISHER_SLOTS + 1) + slot` (the last
    /// slot of each source type is the shared overflow slot).
    ent: [EntityState; N_ENT],
    div: [[Persist; N_AXIS]; N_ENT],
    unc: [[Persist; N_AXIS]; N_ENT],
    /// Indexed by entity pair; boxed (allocated once in `new`) to keep the
    /// monitor small to move.
    cross: Box<[[Persist; N_AXIS]; N_EPAIR]>,
    stats: MonitorStats,
}

fn pair_index(i: usize, j: usize) -> usize {
    let (i, j) = if i < j { (i, j) } else { (j, i) };
    i * (2 * N_ENT - i - 1) / 2 + (j - i - 1)
}

/// `[lo, hi]` mapped to the band of magnitudes it implies.
fn abs_band(lo: f64, hi: f64) -> (f64, f64) {
    if lo >= 0.0 {
        (lo, hi)
    } else if hi <= 0.0 {
        (-hi, -lo)
    } else {
        (0.0, (-lo).max(hi))
    }
}

fn secs_to_ns(s: f64) -> u64 {
    // `as` saturates and maps NaN to 0; inputs are validated finite anyway.
    (s * NS_PER_S) as u64
}

impl ConsistencyMonitor {
    /// Validate the configuration and allocate the command ring. The only
    /// allocations the monitor ever makes happen here.
    pub fn new(cfg: MonitorConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        let ring = CommandRing::new(cfg.command_capacity);
        let variants = [
            Variant {
                latency_ns: cfg.latency_min_ns,
                e: [None; N_AXIS],
            },
            Variant {
                latency_ns: cfg.latency_max_ns,
                e: [None; N_AXIS],
            },
        ];
        Ok(ConsistencyMonitor {
            cfg,
            ring,
            variants,
            model_t: None,
            warmup_until: 0,
            suppress_until: [0; N_AXIS],
            stop_active: false,
            stop_changed_at: None,
            agg: [SourceAgg::default(); N_SRC],
            ent: [EntityState::default(); N_ENT],
            div: [[Persist::default(); N_AXIS]; N_ENT],
            unc: [[Persist::default(); N_AXIS]; N_ENT],
            cross: Box::new([[Persist::default(); N_AXIS]; N_EPAIR]),
            stats: MonitorStats::default(),
        })
    }

    /// The configuration in use.
    pub fn config(&self) -> &MonitorConfig {
        &self.cfg
    }

    /// Counters.
    pub fn stats(&self) -> MonitorStats {
        self.stats
    }

    /// Capacity of the command ring (constant for the monitor's lifetime).
    pub fn command_capacity(&self) -> usize {
        self.ring.capacity()
    }

    /// Whether a safety stop is currently declared.
    pub fn safety_stop_active(&self) -> bool {
        self.stop_active
    }

    /// The expected band `[lo, hi]` for an axis at the model's current time,
    /// or `None` while there is no expectation (warm-up, unspecified axis,
    /// settling after an unknown period, disabled axis).
    pub fn expected_band(&self, axis: Axis) -> Option<(f64, f64)> {
        self.band(self.model_t?, axis.index())
    }

    // ---------------------------------------------------------------- events

    /// Record an observed motion command.
    pub fn on_command<F: FnMut(Finding)>(&mut self, cmd: &CommandSample<'_>, mut sink: F) {
        self.stats.commands = self.stats.commands.saturating_add(1);
        if !self.cfg.command_channels.is_empty()
            && !self.cfg.command_channels.iter().any(|c| c == cmd.channel)
        {
            self.stats.commands_ignored = self.stats.commands_ignored.saturating_add(1);
            return;
        }
        let t = self.clamp_time(cmd.t_ns);
        self.advance_to(t);
        let signed = cmd.direction_known && !self.cfg.compare_magnitudes;
        let mut v = [None; N_AXIS];
        for a in Axis::ALL {
            v[a.index()] = cmd.axis(a).map(|x| {
                if x.is_finite() {
                    self.normalise(a, signed, x)
                } else {
                    self.stats.invalid_command_values =
                        self.stats.invalid_command_values.saturating_add(1);
                    0.0
                }
            });
        }
        if let Some(ev) = self.ring.push(CmdRec { t, v, signed }) {
            if ev.t > t.saturating_sub(self.cfg.latency_max_ns) {
                self.stats.history_underruns = self.stats.history_underruns.saturating_add(1);
            }
        }
        self.check_stale(t, &mut sink);
    }

    /// Declare the platform's safety stop (e-stop, protective stop) state.
    /// While active the expected motion is zero, under-motion is legitimate,
    /// and uncommanded-motion checks wait `safety_stop_grace_ns` for
    /// coast-down. RoboDR only *reads* this state; it never sets it.
    pub fn set_safety_stop(&mut self, now_ns: u64, active: bool) {
        let t = self.clamp_time(now_ns);
        self.advance_to(t);
        if active != self.stop_active {
            self.stop_active = active;
            self.stop_changed_at = Some(t);
        }
    }

    /// Advance time without a sample (drives stale-feedback detection when
    /// feedback stops arriving). Call at a fixed rate, e.g. 10 Hz.
    pub fn tick<F: FnMut(Finding)>(&mut self, now_ns: u64, mut sink: F) {
        let t = self.clamp_time(now_ns);
        self.advance_to(t);
        self.check_stale(t, &mut sink);
    }

    /// Process one feedback sample received at observer time `now_ns`, from
    /// an unknown / single publisher ([`PublisherKey::UNKNOWN`]). Prefer
    /// [`Self::on_feedback_from`] whenever the publisher identity is known.
    pub fn on_feedback<F: FnMut(Finding)>(&mut self, now_ns: u64, fb: &FeedbackSample, sink: F) {
        self.on_feedback_key(now_ns, PublisherKey::UNKNOWN, fb, sink);
    }

    /// Process one feedback sample from the publisher with DDS writer GUID
    /// `guid` (all 16 bytes: prefix + entity id). Preferred: GUIDs are
    /// compared exactly, so an adversary cannot share the real writer's
    /// state slot by choosing a colliding GUID. Same as
    /// [`Self::on_feedback_key`] with [`PublisherKey::Guid`].
    pub fn on_feedback_guid<F: FnMut(Finding)>(
        &mut self,
        now_ns: u64,
        guid: &[u8; 16],
        fb: &FeedbackSample,
        sink: F,
    ) {
        self.on_feedback_key(now_ns, PublisherKey::Guid(*guid), fb, sink);
    }

    /// Backward-compatible form of [`Self::on_feedback_key`] with a
    /// caller-chosen `u32` id (an interned dense id, or the legacy
    /// [`crate::publisher_id`] hash, which an adversary choosing its GUID
    /// can collide: prefer [`Self::on_feedback_guid`]). `Id` keys never
    /// collide with `Guid` keys.
    pub fn on_feedback_from<F: FnMut(Finding)>(
        &mut self,
        now_ns: u64,
        publisher: u32,
        fb: &FeedbackSample,
        sink: F,
    ) {
        self.on_feedback_key(now_ns, PublisherKey::Id(publisher), fb, sink);
    }

    /// Process one feedback sample received at observer time `now_ns` from
    /// `publisher`. All per-sample state (stamps, frozen, NaN, command and
    /// cross-sensor persistence) is kept per (source type, publisher) in a
    /// fixed table that stores the key inline and compares it exactly (no
    /// hashing, no allocation). Publishers interleaving on one source type
    /// raise `robot.motion.multiple_feedback_publishers`; more than
    /// [`PUBLISHER_SLOTS`] concurrent publishers share a dedicated overflow
    /// slot and raise it too ([`Evidence::PublisherOverflow`]).
    pub fn on_feedback_key<F: FnMut(Finding)>(
        &mut self,
        now_ns: u64,
        publisher: PublisherKey,
        fb: &FeedbackSample,
        mut sink: F,
    ) {
        self.stats.feedback = self.stats.feedback.saturating_add(1);
        let now = self.clamp_time(now_ns);
        self.advance_to(now);
        let si = fb.source.index();
        let sc = *self.cfg.sources.get(fb.source);
        let rearm = self.cfg.rearm_clean_samples;
        let slot = self.slot_for(si, publisher, now);
        let e = si * ENT_PER_SRC + slot;
        let pubtag = Some(publisher);
        if slot == OVERFLOW_SLOT && !self.agg[si].overflow_latched {
            self.agg[si].overflow_latched = true;
            self.emit(
                &mut sink,
                rules::MULTIPLE_FEEDBACK_PUBLISHERS,
                Severity::High,
                now,
                Evidence::PublisherOverflow {
                    source: fb.source,
                    publisher,
                    slots: PUBLISHER_SLOTS as u32,
                },
                pubtag,
            );
        }

        // 0. Publisher interleaving.
        self.check_publishers(si, e, publisher, now, fb.source, &mut sink);

        // 1. Stamp integrity (per publisher).
        if sc.stamp_check {
            let prev = self.ent[e].last_stamp;
            let anomaly = match prev {
                Some(p) if fb.t_ns < p => Some(StampAnomaly::Backwards),
                _ if fb.t_ns > now.saturating_add(self.cfg.max_future_skew_ns) => {
                    Some(StampAnomaly::Future)
                }
                Some(p) if fb.t_ns == p => Some(StampAnomaly::Duplicate),
                _ => match self.cfg.max_stamp_age_ns {
                    Some(max) if now.saturating_sub(fb.t_ns) > max => Some(StampAnomaly::Late),
                    _ => None,
                },
            };
            for k in 0..4 {
                if anomaly.map(|a| a.index()) != Some(k) {
                    self.ent[e].stamp_latch[k].ok(rearm);
                }
            }
            if let Some(a) = anomaly {
                if self.ent[e].stamp_latch[a.index()].trip() {
                    let sev = match a {
                        StampAnomaly::Backwards | StampAnomaly::Future => Severity::High,
                        StampAnomaly::Duplicate | StampAnomaly::Late => Severity::Medium,
                    };
                    self.emit(
                        &mut sink,
                        rules::FROZEN_FEEDBACK,
                        sev,
                        now,
                        Evidence::TimestampAnomaly {
                            source: fb.source,
                            anomaly: a,
                            stamp_ns: fb.t_ns,
                            prev_stamp_ns: prev,
                            now_ns: now,
                        },
                        pubtag,
                    );
                }
                if a == StampAnomaly::Duplicate {
                    // A duplicate carries no new information; counting it
                    // would inflate persistence.
                    self.stats.duplicates_skipped = self.stats.duplicates_skipped.saturating_add(1);
                    self.ent[e].last_rx = now;
                    return;
                }
            }
        }
        {
            let st = &mut self.ent[e];
            st.last_stamp = Some(fb.t_ns);
            st.seen = true;
            st.last_rx = now;
            let ag = &mut self.agg[si];
            ag.seen = true;
            ag.last_rx = now;
            ag.stale_latched = false;
        }

        // 2. Sanitise values. A non-finite value is skipped: it is neither a
        //    good nor a bad sample, so it cannot reset persistence, and the
        //    last finite value stays available to the cross-check.
        let mut vals = [None; N_AXIS];
        let mut bits = [None; N_AXIS];
        let mut any_invalid = false;
        for a in Axis::ALL {
            let ai = a.index();
            if !self.cfg.axis(a).enabled {
                continue;
            }
            let Some(raw) = fb.axis(a) else { continue };
            if raw.is_finite() {
                bits[ai] = Some(raw.to_bits());
                self.ent[e].nonfinite_latch[ai].ok(rearm);
                let v = self.normalise(a, sc.signed, raw);
                vals[ai] = Some(v);
                self.agg[si].reported[ai] = true;
                self.ent[e].last_val[ai] = Some((v, now));
                self.check_jump(e, a, v, fb.t_ns, now, fb.source, pubtag, &mut sink);
                self.nan_window(e, a, false, now, fb.source, pubtag, &mut sink);
            } else {
                any_invalid = true;
                self.stats.invalid_feedback_values =
                    self.stats.invalid_feedback_values.saturating_add(1);
                if self.ent[e].nonfinite_latch[ai].trip() {
                    self.emit(
                        &mut sink,
                        rules::INVALID_FEEDBACK,
                        Severity::Medium,
                        now,
                        Evidence::NonFiniteFeedback {
                            source: fb.source,
                            axis: a,
                        },
                        pubtag,
                    );
                }
                self.nan_window(e, a, true, now, fb.source, pubtag, &mut sink);
            }
        }

        // 3. Frozen values (bit-identical while commanded to move). A sample
        //    with a non-finite value is skipped entirely, so sprinkling NaN
        //    cannot break a frozen run either.
        if !any_invalid {
            if sc.frozen_check {
                self.check_frozen(e, fb.source, sc.signed, now, bits, pubtag, &mut sink);
            }
            self.ent[e].prev_bits = Some(bits);
        }

        // 4. Against the command model.
        if sc.command_check {
            for a in Axis::ALL {
                self.check_command(
                    e,
                    &sc,
                    fb.source,
                    a,
                    vals[a.index()],
                    now,
                    pubtag,
                    &mut sink,
                );
            }
        }

        // 5. Cross-sensor.
        if sc.cross_check {
            self.check_cross(e, fb.source, sc.signed, vals, now, pubtag, &mut sink);
        }

        self.check_stale(now, &mut sink);
    }

    // ------------------------------------------------------------- internals

    fn emit<F: FnMut(Finding)>(
        &mut self,
        sink: &mut F,
        rule: &'static str,
        severity: Severity,
        t_ns: u64,
        evidence: Evidence,
        publisher: Option<PublisherKey>,
    ) {
        self.stats.findings = self.stats.findings.saturating_add(1);
        sink(Finding {
            rule,
            severity,
            t_ns,
            evidence,
            publisher,
        });
    }

    /// Signed value, or its magnitude when the axis/input has no sign.
    fn normalise(&self, a: Axis, signed: bool, x: f64) -> f64 {
        if a == Axis::Joint || !signed || self.cfg.compare_magnitudes {
            x.abs()
        } else {
            x
        }
    }

    /// The state slot for `publisher` on source `si`: its own slot, else a
    /// free or expired one (reset), else the source type's overflow slot,
    /// which no single publisher ever owns. Keys are compared exactly.
    fn slot_for(&mut self, si: usize, publisher: PublisherKey, now: u64) -> usize {
        let base = si * ENT_PER_SRC;
        let expiry = self.cfg.publisher_expiry_ns;
        let ov = &self.ent[base + OVERFLOW_SLOT];
        if !ov.seen || now.saturating_sub(ov.last_rx) > expiry {
            self.agg[si].overflow_latched = false;
        }
        if let Some(k) =
            (0..PUBLISHER_SLOTS).find(|&k| self.ent[base + k].publisher == Some(publisher))
        {
            return k;
        }
        for k in 0..PUBLISHER_SLOTS {
            let st = &self.ent[base + k];
            if st.publisher.is_none() || now.saturating_sub(st.last_rx) > expiry {
                self.reset_entity(base + k);
                self.ent[base + k].publisher = Some(publisher);
                return k;
            }
        }
        self.stats.publisher_overflow = self.stats.publisher_overflow.saturating_add(1);
        OVERFLOW_SLOT
    }

    fn reset_entity(&mut self, e: usize) {
        self.ent[e] = EntityState::default();
        self.div[e] = [Persist::default(); N_AXIS];
        self.unc[e] = [Persist::default(); N_AXIS];
        for o in 0..N_ENT {
            if o != e {
                self.cross[pair_index(e, o)] = [Persist::default(); N_AXIS];
            }
        }
    }

    /// Raise `multiple_feedback_publishers` when a publisher resumes after a
    /// different one published for the same source type while it was still
    /// active (interleaving). A clean hand-over (old publisher stops, new one
    /// starts, e.g. a driver restart) does not fire.
    fn check_publishers<F: FnMut(Finding)>(
        &mut self,
        si: usize,
        e: usize,
        publisher: PublisherKey,
        now: u64,
        source: FeedbackSource,
        sink: &mut F,
    ) {
        let expiry = self.cfg.publisher_expiry_ns;
        let base = si * ENT_PER_SRC;
        let active_others = (base..base + ENT_PER_SRC)
            .filter(|&o| {
                o != e && self.ent[o].seen && now.saturating_sub(self.ent[o].last_rx) <= expiry
            })
            .count() as u32;
        let me = self.ent[e];
        let ag = self.agg[si];
        let interleaved = match ag.last_pub {
            Some(lp) if lp != publisher => me.seen && now.saturating_sub(me.last_rx) <= expiry,
            _ => false,
        };
        if interleaved && !ag.multi_latched {
            self.agg[si].multi_latched = true;
            self.agg[si].multi_clean = 0;
            self.emit(
                sink,
                rules::MULTIPLE_FEEDBACK_PUBLISHERS,
                Severity::High,
                now,
                Evidence::MultiplePublishers {
                    source,
                    publisher,
                    other: ag.last_pub.unwrap_or(PublisherKey::UNKNOWN),
                    active: active_others.saturating_add(1).max(2),
                },
                Some(publisher),
            );
        }
        let ag = &mut self.agg[si];
        if active_others == 0 {
            ag.multi_clean = ag.multi_clean.saturating_add(1);
            if ag.multi_clean >= self.cfg.rearm_clean_samples {
                ag.multi_latched = false;
                ag.multi_clean = 0;
            }
        } else {
            ag.multi_clean = 0;
        }
        ag.last_pub = Some(publisher);
    }

    /// Track non-finite values over the last 64 samples of one entity/axis
    /// and escalate to High when their rate is high while motion matters.
    #[allow(clippy::too_many_arguments)]
    fn nan_window<F: FnMut(Finding)>(
        &mut self,
        e: usize,
        a: Axis,
        invalid: bool,
        now: u64,
        source: FeedbackSource,
        publisher: Option<PublisherKey>,
        sink: &mut F,
    ) {
        let ai = a.index();
        let st = &mut self.ent[e];
        st.nan_hist[ai] = (st.nan_hist[ai] << 1) | u64::from(invalid);
        st.nan_n[ai] = st.nan_n[ai].saturating_add(1).min(64);
        let n = u32::from(st.nan_n[ai]);
        let bad = st.nan_hist[ai].count_ones();
        let rate = f64::from(bad) / f64::from(n);
        let thr = self.cfg.nan_rate_high;
        if rate < thr / 2.0 {
            st.nan_rate_latched[ai] = false;
        }
        if !invalid || st.nan_rate_latched[ai] || n < self.cfg.nan_rate_min_samples || rate < thr {
            return;
        }
        let still = self.cfg.axis(a).still_threshold;
        let observed = st.last_val[ai].is_some_and(|(v, _)| v.abs() > still);
        // Nothing valid in the whole window: the motion state is unknown,
        // which is never reported as "fine", even at rest.
        let blind = bad == n;
        let episode = self.unc[e][ai].since.is_some() || self.div[e][ai].since.is_some();
        if blind || observed || episode || self.moving_expected(now, ai) {
            self.ent[e].nan_rate_latched[ai] = true;
            self.emit(
                sink,
                rules::INVALID_FEEDBACK,
                Severity::High,
                now,
                Evidence::NonFiniteRate {
                    source,
                    axis: a,
                    invalid: bad,
                    window: n,
                },
                publisher,
            );
        }
    }

    /// Implausible-jump check between consecutive finite samples of one
    /// entity/axis (see `MonitorConfig::jump_accel_factor`).
    #[allow(clippy::too_many_arguments)]
    fn check_jump<F: FnMut(Finding)>(
        &mut self,
        e: usize,
        a: Axis,
        v: f64,
        stamp: u64,
        now: u64,
        source: FeedbackSource,
        publisher: Option<PublisherKey>,
        sink: &mut F,
    ) {
        let ai = a.index();
        let prev = self.ent[e].prev_fin[ai].replace((v, stamp, now));
        let model = self.cfg.axis(a);
        let (Some(acc), Some((pv, ps, prx))) = (model.max_accel, prev) else {
            return;
        };
        if self.cfg.jump_min_count == 0 {
            return;
        }
        let window = self.cfg.jump_window_ns;
        let ep = &mut self.ent[e].jump[ai];
        if ep.last.is_some_and(|l| now.saturating_sub(l) > window) {
            *ep = JumpEpisode::default();
        }
        // The more lenient of the two gaps (an injector controls stamps, but
        // interleaving within one stamp-checked stream bounds both).
        let dt_ns = stamp.saturating_sub(ps).max(now.saturating_sub(prx)).max(1);
        let dt = dt_ns as f64 / NS_PER_S;
        let dv = (v - pv).abs();
        let tol = model.cross_abs_tol + model.cross_rel_tol * v.abs().max(pv.abs());
        if !(dv > tol && dv > self.cfg.jump_accel_factor * acc * dt) {
            return;
        }
        if ep.last.is_none() {
            ep.since = now;
        }
        ep.last = Some(now);
        ep.count = ep.count.saturating_add(1);
        if ep.fired || ep.count < self.cfg.jump_min_count {
            return;
        }
        ep.fired = true;
        let (jumps, since) = (ep.count, ep.since);
        self.emit(
            sink,
            rules::INCONSISTENT_FEEDBACK_STREAM,
            Severity::High,
            now,
            Evidence::InconsistentStream {
                source,
                axis: a,
                jumps,
                from: pv,
                to: v,
                implied_rate: dv / dt,
                since_ns: since,
            },
            publisher,
        );
    }

    /// Observer time must not go backwards; clamp and count.
    fn clamp_time(&mut self, t: u64) -> u64 {
        match self.model_t {
            Some(m) if t < m => {
                self.stats.clock_regressions = self.stats.clock_regressions.saturating_add(1);
                m
            }
            _ => t,
        }
    }

    /// Model input for one variant at time `t`. `None` = unspecified axis.
    fn input_at(&self, t: u64, lat: u64, ai: usize) -> Option<f64> {
        if self.stop_active {
            return Some(0.0);
        }
        let at = t.saturating_sub(lat);
        match self.ring.at(at) {
            None => Some(0.0),
            Some(r) => {
                if let Some(h) = self.cfg.command_timeout_ns {
                    if at.saturating_sub(r.t) > h {
                        return Some(0.0);
                    }
                }
                r.v[ai]
            }
        }
    }

    /// Whether the command in effect for a variant at `t` carries its sign.
    /// "No command" / timed-out / safety stop mean rest, which has no
    /// direction to get wrong.
    fn input_signed_at(&self, t: u64, lat: u64) -> bool {
        if self.stop_active {
            return true;
        }
        let at = t.saturating_sub(lat);
        match self.ring.at(at) {
            None => true,
            Some(r) => match self.cfg.command_timeout_ns {
                Some(h) if at.saturating_sub(r.t) > h => true,
                _ => r.signed,
            },
        }
    }

    /// Next time strictly after `t` at which a variant's input may change.
    fn next_change(&self, t: u64, lat: u64) -> u64 {
        let mut next = self.ring.next_effect_after(t, lat).unwrap_or(u64::MAX);
        if let Some(h) = self.cfg.command_timeout_ns {
            if let Some(r) = self.ring.at(t.saturating_sub(lat)) {
                let exp = r.t.saturating_add(h).saturating_add(lat).saturating_add(1);
                if exp > t {
                    next = next.min(exp);
                }
            }
        }
        next
    }

    /// Integrate both model variants from `model_t` to `now`, piecewise
    /// exactly between input change points. Bounded by the ring size.
    fn advance_to(&mut self, now: u64) {
        let Some(t0) = self.model_t else {
            // First event: assume rest; warm-up covers the unknown truth.
            self.model_t = Some(now);
            self.warmup_until = now.saturating_add(self.cfg.warmup_ns);
            for v in 0..2 {
                for a in Axis::ALL {
                    if self.cfg.axis(a).enabled {
                        self.variants[v].e[a.index()] = Some(0.0);
                    }
                }
            }
            return;
        };
        if now <= t0 {
            return;
        }
        for vi in 0..2 {
            let lat = self.variants[vi].latency_ns;
            let mut t = t0;
            while t < now {
                let seg_end = self.next_change(t, lat).min(now);
                let dt = (seg_end - t) as f64 / NS_PER_S;
                for a in Axis::ALL {
                    let m = self.cfg.axis(a);
                    if !m.enabled {
                        continue;
                    }
                    let ai = a.index();
                    let u = self.input_at(t, lat, ai);
                    let next = match (self.variants[vi].e[ai], u) {
                        (_, None) => None,
                        (None, Some(u)) => {
                            // Expectation resumes from an unknown state:
                            // start at the target and suppress checks until
                            // the true state could have settled.
                            let ramp = match m.max_accel {
                                Some(acc) => u.abs() / acc,
                                None => 0.0,
                            };
                            let settle = secs_to_ns(5.0 * m.tau_s + ramp)
                                .saturating_add(self.cfg.latency_max_ns - self.cfg.latency_min_ns);
                            let until = t.saturating_add(settle);
                            if until > self.suppress_until[ai] {
                                self.suppress_until[ai] = until;
                            }
                            Some(u)
                        }
                        (Some(e), Some(u)) => {
                            Some(first_order_step(e, u, dt, m.tau_s, m.max_accel))
                        }
                    };
                    self.variants[vi].e[ai] = next;
                }
                t = seg_end;
            }
        }
        self.model_t = Some(now);
    }

    fn band(&self, now: u64, ai: usize) -> Option<(f64, f64)> {
        if now < self.warmup_until || now < self.suppress_until[ai] {
            return None;
        }
        let a = self.variants[0].e[ai]?;
        let b = self.variants[1].e[ai]?;
        Some((a.min(b), a.max(b)))
    }

    fn moving_expected(&self, now: u64, ai: usize) -> bool {
        let still = self.cfg.axis(Axis::ALL[ai]).still_threshold;
        match self.band(now, ai) {
            Some((lo, hi)) => lo > still || hi < -still,
            None => false,
        }
    }

    fn in_stop_grace(&self, now: u64) -> bool {
        match self.stop_changed_at {
            Some(t) => now.saturating_sub(t) < self.cfg.safety_stop_grace_ns,
            None => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_command<F: FnMut(Finding)>(
        &mut self,
        si: usize,
        sc: &crate::config::SourceConfig,
        source: FeedbackSource,
        a: Axis,
        val: Option<f64>,
        now: u64,
        publisher: Option<PublisherKey>,
        sink: &mut F,
    ) {
        let ai = a.index();
        let Some(m) = val else { return };
        let Some((lo, hi)) = self.band(now, ai) else {
            self.div[si][ai].interrupt();
            self.unc[si][ai].interrupt();
            return;
        };
        // Direction is only judged when both the command in effect and the
        // feedback carry their sign; otherwise compare magnitudes.
        let signed = sc.signed
            && self.input_signed_at(now, self.variants[0].latency_ns)
            && self.input_signed_at(now, self.variants[1].latency_ns);
        let (m, (lo, hi)) = if signed {
            (m, (lo, hi))
        } else {
            (m.abs(), abs_band(lo, hi))
        };
        let model = self.cfg.axis(a);
        let tol = model.abs_tol + model.rel_tol * lo.abs().max(hi.abs());
        let still = model.still_threshold;
        let critical = model.uncommanded_critical;

        let direction = if m >= lo - tol && m <= hi + tol {
            None
        } else if lo >= 0.0 {
            Some(if m > hi + tol {
                Direction::Over
            } else if m < -tol {
                Direction::Opposite
            } else {
                Direction::Under
            })
        } else if hi <= 0.0 {
            Some(if m < lo - tol {
                Direction::Over
            } else if m > tol {
                Direction::Opposite
            } else {
                Direction::Under
            })
        } else {
            Some(Direction::Over)
        };

        let eps = self.cfg.rest_command_eps;
        let u_min = self.input_at(now, self.variants[0].latency_ns, ai);
        let u_max = self.input_at(now, self.variants[1].latency_ns, ai);
        let at_rest =
            matches!((u_min, u_max), (Some(x), Some(y)) if x.abs() <= eps && y.abs() <= eps);

        let grace = self.in_stop_grace(now);
        let uncommanded = at_rest
            && m.abs() > still
            && matches!(direction, Some(Direction::Over | Direction::Opposite))
            && !(self.stop_active && grace);
        // While the command is at rest, only the uncommanded rule judges:
        // under-motion there is just braking harder than modelled, and
        // over-motion within the noise floor / coast-down grace is benign.
        let divergence = !uncommanded
            && !at_rest
            && match direction {
                None => false,
                Some(Direction::Under) => !(self.stop_active || grace),
                Some(_) => true,
            };

        let hold = self.cfg.episode_hold_ns;
        let p_unc = self.cfg.uncommanded;
        if let Some(fire) =
            self.unc[si][ai].observe_held(uncommanded, m, critical, now, hold, &p_unc)
        {
            // Severity and evidence use the episode's critical-sample count
            // and peak, not the sample that happened to complete the rule
            // (which may be a plausible value interleaved by an injector).
            let sev = if fire.critical {
                Severity::Critical
            } else {
                Severity::High
            };
            let (since, n, peak) = (fire.since, fire.bad, fire.peak);
            self.emit(
                sink,
                rules::UNCOMMANDED_MOTION,
                sev,
                now,
                Evidence::UncommandedMotion {
                    source,
                    axis: a,
                    measured: if m.abs() >= peak { m } else { peak.copysign(m) },
                    expected_abs_max: lo.abs().max(hi.abs()),
                    tolerance: tol,
                    since_ns: since,
                    samples: n,
                },
                publisher,
            );
        }
        // The divergence episode counts its *opposite-direction* samples at
        // or above `uncommanded_critical` (other directions contribute 0):
        // `min_samples` of them make it Critical, and a latched High/Medium
        // episode (e.g. one pre-opened by mild under-motion) escalates once.
        // With the hold, interleaved plausible samples cannot dilute it.
        let p_div = self.cfg.divergence;
        let opp_mag = if direction == Some(Direction::Opposite) {
            m.abs()
        } else {
            0.0
        };
        if let Some(fire) =
            self.div[si][ai].observe_held(divergence, opp_mag, critical, now, hold, &p_div)
        {
            let (since, n) = (fire.since, fire.bad);
            let mut dir = direction.unwrap_or(Direction::Over);
            let mut measured = m;
            let sev = if fire.critical {
                // Report the episode's opposite-direction peak (the sample
                // completing the rule may be a different, milder one).
                dir = Direction::Opposite;
                if measured.abs() < fire.peak || direction != Some(Direction::Opposite) {
                    measured = if lo >= 0.0 { -fire.peak } else { fire.peak };
                }
                Severity::Critical
            } else {
                match dir {
                    Direction::Under if !self.cfg.safety_stop_signal_wired => Severity::Medium,
                    // Driving / turning against the command at speed is as
                    // hazardous as uncommanded motion: a firing sample at
                    // that speed is Critical at once.
                    Direction::Opposite if m.abs() >= critical => {
                        self.div[si][ai].mark_critical();
                        Severity::Critical
                    }
                    _ => Severity::High,
                }
            };
            self.emit(
                sink,
                rules::FEEDBACK_DIVERGENCE,
                sev,
                now,
                Evidence::FeedbackDivergence {
                    source,
                    axis: a,
                    direction: dir,
                    commanded: u_min,
                    expected_lo: lo,
                    expected_hi: hi,
                    tolerance: tol,
                    measured,
                    since_ns: since,
                    samples: n,
                },
                publisher,
            );
        }
    }

    /// Frozen values: a run of bit-identical samples while the band says
    /// the robot moves. A steady cruise legitimately repeats values on a
    /// noise-free quantised sensor, so the run fires only once the
    /// *expectation* changed during it (the band midpoint on some reported
    /// axis moved by at least `frozen_change_factor * abs_tol`): the robot
    /// should have accelerated / decelerated / turned, and a live sensor
    /// would have shown it.
    #[allow(clippy::too_many_arguments)]
    fn check_frozen<F: FnMut(Finding)>(
        &mut self,
        si: usize,
        source: FeedbackSource,
        signed: bool,
        now: u64,
        bits: [Option<u64>; N_AXIS],
        publisher: Option<PublisherKey>,
        sink: &mut F,
    ) {
        let any = bits.iter().any(Option::is_some);
        let identical = any && self.ent[si].prev_bits == Some(bits);
        let moving = (0..N_AXIS).any(|ai| bits[ai].is_some() && self.moving_expected(now, ai))
            && !self.stop_active;
        if identical && moving {
            let factor = self.cfg.frozen_change_factor;
            let mut changed = false;
            for a in Axis::ALL {
                let ai = a.index();
                if bits[ai].is_none() {
                    continue;
                }
                let Some((lo, hi)) = self.band(now, ai) else {
                    continue;
                };
                let (lo, hi) = if signed && a != Axis::Joint {
                    (lo, hi)
                } else {
                    abs_band(lo, hi)
                };
                let mid = (lo + hi) / 2.0;
                let st = &mut self.ent[si];
                let r = match st.frozen_mid[ai] {
                    // A new run (count 0) starts its range afresh.
                    Some((mn, mx)) if st.frozen_count > 0 => (mn.min(mid), mx.max(mid)),
                    _ => (mid, mid),
                };
                st.frozen_mid[ai] = Some(r);
                if r.1 - r.0 >= factor * self.cfg.axis(a).abs_tol {
                    changed = true;
                }
            }
            let st = &mut self.ent[si];
            if st.frozen_count == 0 {
                st.frozen_since = now;
            }
            st.frozen_count = st.frozen_count.saturating_add(1);
            let (count, since) = (st.frozen_count, st.frozen_since);
            if !st.frozen_latched
                && changed
                && count >= self.cfg.frozen_min_samples
                && now.saturating_sub(since) >= self.cfg.frozen_min_duration_ns
            {
                st.frozen_latched = true;
                self.emit(
                    sink,
                    rules::FROZEN_FEEDBACK,
                    Severity::High,
                    now,
                    Evidence::FrozenValues {
                        source,
                        repeats: count,
                        since_ns: since,
                    },
                    publisher,
                );
            }
        } else {
            let st = &mut self.ent[si];
            st.frozen_count = 0;
            st.frozen_mid = [None; N_AXIS];
            if !identical {
                st.frozen_latched = false;
            }
        }
    }

    /// Compare this entity's values with the latest of every publisher of
    /// every other cross-checked source type. Signed when both sides are
    /// signed sources, magnitudes otherwise.
    #[allow(clippy::too_many_arguments)]
    fn check_cross<F: FnMut(Finding)>(
        &mut self,
        e: usize,
        source: FeedbackSource,
        signed: bool,
        vals: [Option<f64>; N_AXIS],
        now: u64,
        publisher: Option<PublisherKey>,
        sink: &mut F,
    ) {
        let skew = self.cfg.cross_max_skew_ns;
        let p = self.cfg.cross_sensor;
        let hold = self.cfg.episode_hold_ns;
        let si = source.index();
        for oe in 0..N_ENT {
            let other = FeedbackSource::ALL[oe / ENT_PER_SRC];
            let osc = *self.cfg.sources.get(other);
            if other.index() == si || !osc.cross_check || !self.ent[oe].seen {
                continue;
            }
            let both_signed = signed && osc.signed;
            let pi = pair_index(e, oe);
            for a in Axis::ALL {
                let ai = a.index();
                let Some(mine) = vals[ai] else { continue };
                let Some((theirs, rx)) = self.ent[oe].last_val[ai] else {
                    continue;
                };
                if now.saturating_sub(rx) > skew {
                    self.cross[pi][ai].interrupt();
                    continue;
                }
                let (mine, theirs) = if both_signed {
                    (mine, theirs)
                } else {
                    (mine.abs(), theirs.abs())
                };
                let model = self.cfg.axis(a);
                let tol = model.cross_abs_tol + model.cross_rel_tol * mine.abs().max(theirs.abs());
                let diff = (mine - theirs).abs();
                let bad = diff > tol;
                // Hold-protected like the command-model rules: agreeing
                // samples within `episode_hold_ns` of a disagreeing one are
                // neutral, so interleaved fakes that agree with the other
                // sensor cannot dilute a real disagreement at any ratio.
                if let Some(Fire { since, bad: n, .. }) =
                    self.cross[pi][ai].observe_held(bad, diff, f64::INFINITY, now, hold, &p)
                {
                    let (sa, va, sb, vb) = if si < other.index() {
                        (source, mine, other, theirs)
                    } else {
                        (other, theirs, source, mine)
                    };
                    let ra = self.cfg.sources.get(sa).trust_rank;
                    let rb = self.cfg.sources.get(sb).trust_rank;
                    let more_trusted = match ra.cmp(&rb) {
                        std::cmp::Ordering::Greater => Some(sa),
                        std::cmp::Ordering::Less => Some(sb),
                        std::cmp::Ordering::Equal => None,
                    };
                    self.emit(
                        sink,
                        rules::CROSS_SENSOR_DISAGREEMENT,
                        Severity::High,
                        now,
                        Evidence::CrossSensorDisagreement {
                            axis: a,
                            source_a: sa,
                            value_a: va,
                            source_b: sb,
                            value_b: vb,
                            tolerance: tol,
                            more_trusted,
                            since_ns: since,
                            samples: n,
                        },
                        publisher,
                    );
                }
            }
        }
    }

    fn check_stale<F: FnMut(Finding)>(&mut self, now: u64, sink: &mut F) {
        if self.stop_active {
            return;
        }
        for s in FeedbackSource::ALL {
            let si = s.index();
            let Some(limit) = self.cfg.sources.get(s).stale_after_ns else {
                continue;
            };
            let st = self.agg[si];
            if !st.seen || st.stale_latched {
                continue;
            }
            let age = now.saturating_sub(st.last_rx);
            if age <= limit {
                continue;
            }
            let moving = (0..N_AXIS).any(|ai| st.reported[ai] && self.moving_expected(now, ai));
            if moving {
                self.agg[si].stale_latched = true;
                self.emit(
                    sink,
                    rules::FROZEN_FEEDBACK,
                    Severity::Medium,
                    now,
                    Evidence::StaleFeedback {
                        source: s,
                        last_rx_ns: st.last_rx,
                        age_ns: age,
                    },
                    None,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_index_is_a_bijection() {
        let mut seen = [false; N_EPAIR];
        for i in 0..N_ENT {
            for j in 0..N_ENT {
                if i == j {
                    continue;
                }
                let p = pair_index(i, j);
                assert_eq!(p, pair_index(j, i));
                assert!(p < N_EPAIR);
                if i < j {
                    assert!(!seen[p]);
                    seen[p] = true;
                }
            }
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn persistence_requires_both_duration_and_samples_and_fires_once() {
        let p = Persistence {
            min_duration_ns: 100,
            min_samples: 3,
            min_bad_fraction: 1.0,
            clear_samples: 2,
        };
        let mut s = Persist::default();
        assert!(s.observe(true, 0, &p).is_none());
        assert!(s.observe(true, 10, &p).is_none());
        assert!(s.observe(true, 20, &p).is_none()); // 3 samples, 20 ns
        assert_eq!(s.observe(true, 100, &p), Some((0, 4)));
        assert!(s.observe(true, 200, &p).is_none()); // latched
        assert!(s.observe(false, 210, &p).is_none());
        assert!(s.observe(true, 220, &p).is_none()); // episode continues, latched
        assert!(s.observe(false, 230, &p).is_none());
        assert!(s.observe(false, 240, &p).is_none()); // 2 consecutive good: re-armed
        for t in [300, 350] {
            assert!(s.observe(true, t, &p).is_none());
        }
        assert_eq!(s.observe(true, 400, &p), Some((300, 3)));
    }

    #[test]
    fn interleaved_good_samples_do_not_reset_an_episode() {
        let p = Persistence {
            min_duration_ns: 100,
            min_samples: 5,
            min_bad_fraction: 0.25,
            clear_samples: 4,
        };
        // bad, good, good, good, bad, ... = 25 % bad: fires.
        let mut s = Persist::default();
        let mut fired = None;
        for k in 0..100u64 {
            if let Some(x) = s.observe(k % 4 == 0, k * 10, &p) {
                fired = Some((k, x));
                break;
            }
        }
        let (k, (since, n)) = fired.expect("diluted episode must still fire");
        assert_eq!(since, 0);
        assert_eq!(n, 5);
        assert_eq!(k, 16);

        // 1 bad in 5 is below the fraction: never fires.
        let mut s = Persist::default();
        for k in 0..1000u64 {
            assert!(s.observe(k % 5 == 0, k * 10, &p).is_none());
        }

        // `clear_samples` consecutive good samples end the episode.
        let mut s = Persist::default();
        for k in 0..4u64 {
            s.observe(true, k, &p);
        }
        for k in 4..8u64 {
            s.observe(false, k, &p);
        }
        assert!(s.since.is_none());
    }

    #[test]
    fn hold_makes_interleaved_good_samples_neutral() {
        let p = Persistence {
            min_duration_ns: 100,
            min_samples: 5,
            min_bad_fraction: 0.25,
            clear_samples: 4,
        };
        // 1 bad in 20 (5 %), good ones within the hold: still fires, and
        // only genuinely bad samples are counted.
        let mut s = Persist::default();
        let mut fired = None;
        for k in 0..200u64 {
            if let Some(f) = s.observe_held(k % 20 == 0, 0.5, f64::INFINITY, k, 25, &p) {
                fired = Some((k, f));
                break;
            }
        }
        let (k, f) = fired.expect("held episode must fire");
        assert_eq!((k, f.since, f.bad, f.critical), (100, 0, 6, false));
        assert_eq!(f.peak, 0.5);

        // Same stream, hold shorter than the bad-sample spacing: diluted.
        let mut s = Persist::default();
        for k in 0..1000u64 {
            assert!(s
                .observe_held(k % 20 == 0, 0.5, f64::INFINITY, k, 5, &p)
                .is_none());
        }

        // After the hold expires, good samples clear the episode as usual.
        let mut s = Persist::default();
        s.observe_held(true, 0.5, f64::INFINITY, 0, 10, &p);
        for t in 1..=10u64 {
            s.observe_held(false, 0.0, f64::INFINITY, t, 10, &p);
        }
        assert!(s.since.is_some(), "neutral samples must not clear");
        for t in 11..15u64 {
            s.observe_held(false, 0.0, f64::INFINITY, t, 10, &p);
        }
        assert!(s.since.is_none());
    }

    #[test]
    fn latched_high_episode_escalates_to_critical_once() {
        let p = Persistence {
            min_duration_ns: 10,
            min_samples: 3,
            min_bad_fraction: 1.0,
            clear_samples: 2,
        };
        let mut s = Persist::default();
        let mut fires = Vec::new();
        for (t, mag) in [
            (0u64, 0.2),
            (5, 0.2),
            (10, 0.2),
            (15, 0.4),
            (20, 0.4),
            (25, 0.2),
        ]
        .into_iter()
        .chain((30..60).map(|t| (t, 0.4)))
        {
            if let Some(f) = s.observe_held(true, mag, 0.3, t, 0, &p) {
                fires.push((t, f.critical, f.peak));
            }
        }
        // High at t = 10, Critical once the third critical sample arrives.
        assert_eq!(fires, vec![(10, false, 0.2), (30, true, 0.4)]);

        // Critical from the start: fires once, no second escalation.
        let mut s = Persist::default();
        let n = (0..50u64)
            .filter(|&t| s.observe_held(true, 0.5, 0.3, t * 5, 0, &p).is_some())
            .count();
        assert_eq!(n, 1);

        // A single critical spike does not make the episode Critical.
        let mut s = Persist::default();
        let mut crit = false;
        for (t, mag) in [(0u64, 0.2), (5, 0.9), (10, 0.2), (15, 0.2)] {
            if let Some(f) = s.observe_held(true, mag, 0.3, t, 0, &p) {
                crit |= f.critical;
                assert_eq!(f.peak, 0.9);
            }
        }
        assert!(!crit);
    }

    #[test]
    fn latch_rearms_after_clean_samples() {
        let mut l = Latch::default();
        assert!(l.trip());
        assert!(!l.trip());
        l.ok(2);
        assert!(!l.trip()); // trip resets the clean count
        l.ok(2);
        l.ok(2);
        assert!(l.trip());
    }
}
