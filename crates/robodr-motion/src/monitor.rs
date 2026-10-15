//! [`ConsistencyMonitor`]: the stateful detector.
//!
//! Per-event path (`on_command`, `on_feedback`, `tick`, `set_safety_stop`)
//! performs **no heap allocation** and is deterministic: all state lives in
//! fixed-size arrays plus one ring buffer allocated in [`ConsistencyMonitor::new`].
//! Findings are handed to a caller-supplied sink as plain `Copy` values;
//! turning one into a [`Deviation`] (which owns a `String`) is the caller's
//! choice and happens off the per-sample path.

use crate::config::{ConfigError, MonitorConfig, Persistence};
use crate::model::{first_order_step, CmdRec, CommandRing};
use crate::sample::{Axis, CommandSample, FeedbackSample, FeedbackSource};
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
}

const N_SRC: usize = 5;
const N_AXIS: usize = 3;
const N_PAIR: usize = N_SRC * (N_SRC - 1) / 2;
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
}

impl Finding {
    /// Human-readable one-liner. Allocates.
    pub fn detail(&self) -> String {
        fn ms(ns: u64) -> u64 {
            ns / 1_000_000
        }
        let age = |since: u64| ms(self.t_ns.saturating_sub(since));
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
}

#[derive(Debug, Clone, Copy, Default)]
struct Persist {
    since: Option<u64>,
    count: u32,
    fired: bool,
    clear: u32,
}

impl Persist {
    /// Feed one observation. Returns `Some((since, count))` exactly once per
    /// episode, when the condition first satisfies the persistence rule.
    fn observe(&mut self, bad: bool, now: u64, p: &Persistence) -> Option<(u64, u32)> {
        if bad {
            self.clear = 0;
            let since = *self.since.get_or_insert(now);
            self.count = self.count.saturating_add(1);
            if !self.fired
                && self.count >= p.min_samples
                && now.saturating_sub(since) >= p.min_duration_ns
            {
                self.fired = true;
                return Some((since, self.count));
            }
        } else {
            self.since = None;
            self.count = 0;
            if self.fired {
                self.clear = self.clear.saturating_add(1);
                if self.clear >= p.clear_samples {
                    self.fired = false;
                    self.clear = 0;
                }
            }
        }
        None
    }

    /// Break the run without counting as a good sample (no basis to judge).
    fn interrupt(&mut self) {
        self.since = None;
        self.count = 0;
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

#[derive(Debug, Clone, Copy, Default)]
struct SourceState {
    seen: bool,
    last_stamp: Option<u64>,
    last_rx: u64,
    reported: [bool; N_AXIS],
    /// Latest finite value per axis and when it was received.
    last_val: [Option<(f64, u64)>; N_AXIS],
    /// Bit patterns of the previous sample's raw values.
    prev_bits: Option<[Option<u64>; N_AXIS]>,
    frozen_count: u32,
    frozen_since: u64,
    frozen_latched: bool,
    stale_latched: bool,
    stamp_latch: [Latch; 4],
    nonfinite_latch: [Latch; N_AXIS],
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
    src: [SourceState; N_SRC],
    div: [[Persist; N_AXIS]; N_SRC],
    unc: [[Persist; N_AXIS]; N_SRC],
    cross: [[Persist; N_AXIS]; N_PAIR],
    stats: MonitorStats,
}

fn pair_index(i: usize, j: usize) -> usize {
    let (i, j) = if i < j { (i, j) } else { (j, i) };
    i * (2 * N_SRC - i - 1) / 2 + (j - i - 1)
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
            src: [SourceState::default(); N_SRC],
            div: [[Persist::default(); N_AXIS]; N_SRC],
            unc: [[Persist::default(); N_AXIS]; N_SRC],
            cross: [[Persist::default(); N_AXIS]; N_PAIR],
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
        let mut v = [None; N_AXIS];
        for a in Axis::ALL {
            v[a.index()] = cmd.axis(a).map(|x| {
                if x.is_finite() {
                    self.normalise(a, x)
                } else {
                    self.stats.invalid_command_values =
                        self.stats.invalid_command_values.saturating_add(1);
                    0.0
                }
            });
        }
        if let Some(ev) = self.ring.push(CmdRec { t, v }) {
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

    /// Process one feedback sample received at observer time `now_ns`.
    pub fn on_feedback<F: FnMut(Finding)>(
        &mut self,
        now_ns: u64,
        fb: &FeedbackSample,
        mut sink: F,
    ) {
        self.stats.feedback = self.stats.feedback.saturating_add(1);
        let now = self.clamp_time(now_ns);
        self.advance_to(now);
        let si = fb.source.index();
        let sc = *self.cfg.sources.get(fb.source);
        let rearm = self.cfg.rearm_clean_samples;

        // 1. Stamp integrity.
        if sc.stamp_check {
            let prev = self.src[si].last_stamp;
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
                    self.src[si].stamp_latch[k].ok(rearm);
                }
            }
            if let Some(a) = anomaly {
                if self.src[si].stamp_latch[a.index()].trip() {
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
                    );
                }
                if a == StampAnomaly::Duplicate {
                    // A duplicate carries no new information; counting it
                    // would inflate persistence.
                    self.stats.duplicates_skipped = self.stats.duplicates_skipped.saturating_add(1);
                    return;
                }
            }
        }
        self.src[si].last_stamp = Some(fb.t_ns);
        self.src[si].seen = true;
        self.src[si].last_rx = now;
        self.src[si].stale_latched = false;

        // 2. Sanitise values.
        let mut vals = [None; N_AXIS];
        let mut bits = [None; N_AXIS];
        for a in Axis::ALL {
            let ai = a.index();
            if !self.cfg.axis(a).enabled {
                continue;
            }
            let Some(raw) = fb.axis(a) else { continue };
            if raw.is_finite() {
                // Only finite values take part in the frozen check: a constant
                // NaN/inf stream is already reported as invalid.
                bits[ai] = Some(raw.to_bits());
                self.src[si].nonfinite_latch[ai].ok(rearm);
                let v = self.normalise(a, raw);
                vals[ai] = Some(v);
                self.src[si].reported[ai] = true;
                self.src[si].last_val[ai] = Some((v, now));
            } else {
                // Unusable value: drop it and break persistence runs so stale
                // context is not stitched across the gap.
                self.src[si].last_val[ai] = None;
                self.div[si][ai].interrupt();
                self.unc[si][ai].interrupt();
                if self.src[si].nonfinite_latch[ai].trip() {
                    self.emit(
                        &mut sink,
                        rules::INVALID_FEEDBACK,
                        Severity::Medium,
                        now,
                        Evidence::NonFiniteFeedback {
                            source: fb.source,
                            axis: a,
                        },
                    );
                }
            }
        }

        // 3. Frozen values (bit-identical while commanded to move).
        if sc.frozen_check {
            self.check_frozen(si, fb.source, now, bits, &mut sink);
        }
        self.src[si].prev_bits = Some(bits);

        // 4. Against the command model.
        if sc.command_check {
            for a in Axis::ALL {
                self.check_command(si, fb.source, a, vals[a.index()], now, &mut sink);
            }
        }

        // 5. Cross-sensor.
        if sc.cross_check {
            self.check_cross(si, fb.source, vals, now, &mut sink);
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
    ) {
        self.stats.findings = self.stats.findings.saturating_add(1);
        sink(Finding {
            rule,
            severity,
            t_ns,
            evidence,
        });
    }

    fn normalise(&self, a: Axis, x: f64) -> f64 {
        if a == Axis::Joint || self.cfg.compare_magnitudes {
            x.abs()
        } else {
            x
        }
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

    fn check_command<F: FnMut(Finding)>(
        &mut self,
        si: usize,
        source: FeedbackSource,
        a: Axis,
        val: Option<f64>,
        now: u64,
        sink: &mut F,
    ) {
        let ai = a.index();
        let Some(m) = val else { return };
        let Some((lo, hi)) = self.band(now, ai) else {
            self.div[si][ai].interrupt();
            self.unc[si][ai].interrupt();
            return;
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

        let p_unc = self.cfg.uncommanded;
        if let Some((since, n)) = self.unc[si][ai].observe(uncommanded, now, &p_unc) {
            let sev = if m.abs() >= critical {
                Severity::Critical
            } else {
                Severity::High
            };
            self.emit(
                sink,
                rules::UNCOMMANDED_MOTION,
                sev,
                now,
                Evidence::UncommandedMotion {
                    source,
                    axis: a,
                    measured: m,
                    expected_abs_max: lo.abs().max(hi.abs()),
                    tolerance: tol,
                    since_ns: since,
                    samples: n,
                },
            );
        }
        let p_div = self.cfg.divergence;
        if let Some((since, n)) = self.div[si][ai].observe(divergence, now, &p_div) {
            let dir = direction.unwrap_or(Direction::Over);
            let sev = match dir {
                Direction::Under if !self.cfg.safety_stop_signal_wired => Severity::Medium,
                _ => Severity::High,
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
                    measured: m,
                    since_ns: since,
                    samples: n,
                },
            );
        }
    }

    fn check_frozen<F: FnMut(Finding)>(
        &mut self,
        si: usize,
        source: FeedbackSource,
        now: u64,
        bits: [Option<u64>; N_AXIS],
        sink: &mut F,
    ) {
        let any = bits.iter().any(Option::is_some);
        let identical = any && self.src[si].prev_bits == Some(bits);
        let moving = (0..N_AXIS).any(|ai| bits[ai].is_some() && self.moving_expected(now, ai))
            && !self.stop_active;
        if identical && moving {
            let st = &mut self.src[si];
            if st.frozen_count == 0 {
                st.frozen_since = now;
            }
            st.frozen_count = st.frozen_count.saturating_add(1);
            let (count, since) = (st.frozen_count, st.frozen_since);
            if !st.frozen_latched
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
                );
            }
        } else {
            let st = &mut self.src[si];
            st.frozen_count = 0;
            if !identical {
                st.frozen_latched = false;
            }
        }
    }

    fn check_cross<F: FnMut(Finding)>(
        &mut self,
        si: usize,
        source: FeedbackSource,
        vals: [Option<f64>; N_AXIS],
        now: u64,
        sink: &mut F,
    ) {
        let skew = self.cfg.cross_max_skew_ns;
        let p = self.cfg.cross_sensor;
        for other in FeedbackSource::ALL {
            let oi = other.index();
            if oi == si || !self.cfg.sources.get(other).cross_check {
                continue;
            }
            let pi = pair_index(si, oi);
            for a in Axis::ALL {
                let ai = a.index();
                let Some(mine) = vals[ai] else { continue };
                let Some((theirs, rx)) = self.src[oi].last_val[ai] else {
                    continue;
                };
                if now.saturating_sub(rx) > skew {
                    self.cross[pi][ai].interrupt();
                    continue;
                }
                let model = self.cfg.axis(a);
                let tol = model.cross_abs_tol + model.cross_rel_tol * mine.abs().max(theirs.abs());
                let bad = (mine - theirs).abs() > tol;
                if let Some((since, n)) = self.cross[pi][ai].observe(bad, now, &p) {
                    let (sa, va, sb, vb) = if si < oi {
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
            let st = self.src[si];
            if !st.seen || st.stale_latched {
                continue;
            }
            let age = now.saturating_sub(st.last_rx);
            if age <= limit {
                continue;
            }
            let moving = (0..N_AXIS).any(|ai| st.reported[ai] && self.moving_expected(now, ai));
            if moving {
                self.src[si].stale_latched = true;
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
        let mut seen = [false; N_PAIR];
        for i in 0..N_SRC {
            for j in 0..N_SRC {
                if i == j {
                    continue;
                }
                let p = pair_index(i, j);
                assert_eq!(p, pair_index(j, i));
                assert!(p < N_PAIR);
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
            clear_samples: 2,
        };
        let mut s = Persist::default();
        assert!(s.observe(true, 0, &p).is_none());
        assert!(s.observe(true, 10, &p).is_none());
        assert!(s.observe(true, 20, &p).is_none()); // 3 samples, 20 ns
        assert_eq!(s.observe(true, 100, &p), Some((0, 4)));
        assert!(s.observe(true, 200, &p).is_none()); // latched
        assert!(s.observe(false, 210, &p).is_none());
        assert!(s.observe(true, 220, &p).is_none()); // run restarted, still latched
        assert!(s.observe(false, 230, &p).is_none());
        assert!(s.observe(false, 240, &p).is_none()); // re-armed
        for t in [300, 350] {
            assert!(s.observe(true, t, &p).is_none());
        }
        assert_eq!(s.observe(true, 400, &p), Some((300, 3)));
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
