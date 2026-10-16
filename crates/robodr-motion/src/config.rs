//! Per-robot-model configuration. Serde-friendly so it can live next to the
//! locked model profile and be signed/versioned with it.
//!
//! All times are nanoseconds. The defaults are a **starting point for a small
//! skid-steer / differential UGV** and are not tuned against real lab traces;
//! see the crate docs, "Tuning".

use crate::sample::{Axis, FeedbackSource};
use serde::{Deserialize, Serialize};
use std::fmt;

const MS: u64 = 1_000_000;

/// Response model and tolerance band for one axis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AxisModel {
    /// Track this axis at all. Disabled axes are ignored by every check.
    pub enabled: bool,
    /// First-order time constant, seconds (0 = instantaneous apart from the
    /// acceleration limit).
    pub tau_s: f64,
    /// Acceleration (rate) limit, units/s^2. `None` = unlimited.
    pub max_accel: Option<f64>,
    /// Absolute half-width added to the expected band.
    pub abs_tol: f64,
    /// Relative half-width, as a fraction of the larger band end.
    pub rel_tol: f64,
    /// Below this magnitude the robot counts as "not moving" on the axis
    /// (noise floor of the feedback).
    pub still_threshold: f64,
    /// Uncommanded motion at or above this magnitude is `Critical`.
    pub uncommanded_critical: f64,
    /// Cross-sensor absolute tolerance.
    pub cross_abs_tol: f64,
    /// Cross-sensor relative tolerance (fraction of the larger reading).
    pub cross_rel_tol: f64,
}

impl Default for AxisModel {
    /// UGV forward-speed defaults (m/s).
    fn default() -> Self {
        AxisModel {
            enabled: true,
            tau_s: 0.25,
            max_accel: Some(2.0),
            abs_tol: 0.10,
            rel_tol: 0.20,
            still_threshold: 0.03,
            uncommanded_critical: 0.30,
            cross_abs_tol: 0.20,
            cross_rel_tol: 0.25,
        }
    }
}

impl AxisModel {
    /// An axis that is not tracked.
    pub fn disabled() -> Self {
        AxisModel {
            enabled: false,
            ..AxisModel::default()
        }
    }

    /// UGV yaw-rate defaults (rad/s).
    pub fn ugv_angular() -> Self {
        AxisModel {
            enabled: true,
            tau_s: 0.20,
            max_accel: Some(4.0),
            abs_tol: 0.15,
            rel_tol: 0.25,
            still_threshold: 0.05,
            uncommanded_critical: 0.50,
            cross_abs_tol: 0.15,
            cross_rel_tol: 0.25,
        }
    }

    /// Manipulator max-joint-speed defaults (rad/s).
    pub fn manipulator_joint() -> Self {
        AxisModel {
            enabled: true,
            tau_s: 0.05,
            max_accel: Some(10.0),
            abs_tol: 0.10,
            rel_tol: 0.20,
            still_threshold: 0.02,
            uncommanded_critical: 0.20,
            cross_abs_tol: 0.10,
            cross_rel_tol: 0.20,
        }
    }
}

/// How long a condition must hold before it fires, and how long it must be
/// clear before the same detector can fire again (one finding per episode).
///
/// An **episode** starts at the first bad sample and lasts until
/// `clear_samples` *consecutive* good samples have been seen. It fires (once)
/// when, on a bad sample,
///
/// * the episode is at least `min_duration_ns` old,
/// * it holds at least `min_samples` bad samples, and
/// * bad samples are at least `min_bad_fraction` of all samples in it.
///
/// Good samples interleaved between bad ones therefore cannot reset the run
/// (a second publisher injecting "all is well" values between real ones only
/// dilutes the fraction). Samples with no basis to judge (NaN, warm-up) are
/// neither good nor bad. For the `divergence` and `uncommanded` rules, good
/// samples within [`MonitorConfig::episode_hold_ns`] of the latest bad one
/// are neutral as well, so they cannot dilute at all.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Persistence {
    /// The episode must be at least this old.
    pub min_duration_ns: u64,
    /// ... contain at least this many bad samples ...
    pub min_samples: u32,
    /// ... which are at least this fraction (0, 1] of its samples. `1.0`
    /// demands an unbroken run.
    pub min_bad_fraction: f64,
    /// Consecutive good samples that end an episode (and re-arm after
    /// firing).
    pub clear_samples: u32,
}

impl Default for Persistence {
    fn default() -> Self {
        Persistence {
            min_duration_ns: 500 * MS,
            min_samples: 10,
            min_bad_fraction: DEFAULT_BAD_FRACTION,
            clear_samples: 10,
        }
    }
}

/// Default `min_bad_fraction`. On its own an injector sending four "at
/// rest" samples per real one would stay under it; `episode_hold_ns` closes
/// that for the command-model rules.
const DEFAULT_BAD_FRACTION: f64 = 0.25;

/// Which checks apply to one feedback source, and how far it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceConfig {
    /// Compare against the command model (divergence, uncommanded motion).
    pub command_check: bool,
    /// Take part in cross-sensor comparison.
    pub cross_check: bool,
    /// Flag bit-identical values while the robot is commanded to move.
    pub frozen_check: bool,
    /// Check stamps (backwards, duplicate, future, late).
    pub stamp_check: bool,
    /// Flag silence longer than this while commanded to move.
    pub stale_after_ns: Option<u64>,
    /// Higher = more trusted. Used to say which side of a cross-sensor
    /// disagreement is more believable; it never suppresses a finding.
    pub trust_rank: u8,
    /// The source reports signed body-frame velocities. `false` for
    /// magnitude-only measurements (GNSS speed over ground): the monitor
    /// then compares magnitudes against it.
    pub signed: bool,
}

impl Default for SourceConfig {
    fn default() -> Self {
        SourceConfig {
            command_check: true,
            cross_check: true,
            frozen_check: true,
            stamp_check: true,
            stale_after_ns: Some(500 * MS),
            trust_rank: 1,
            signed: true,
        }
    }
}

/// Per-source settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceTable {
    pub wheel_odometry: SourceConfig,
    pub imu: SourceConfig,
    pub joint_state: SourceConfig,
    pub gnss: SourceConfig,
    pub other: SourceConfig,
}

impl Default for SourceTable {
    fn default() -> Self {
        SourceTable {
            // Process-authored by the base controller: same compromise domain
            // as the command path. Fully checked, lowest hardware trust.
            wheel_odometry: SourceConfig::default(),
            // Separate device, direct physical measurement (gyro).
            imu: SourceConfig {
                trust_rank: 3,
                ..SourceConfig::default()
            },
            joint_state: SourceConfig::default(),
            // Separate device, but RF-spoofable and laggy/noisy at low speed,
            // with routine dropouts: cross-check only.
            gnss: SourceConfig {
                command_check: false,
                frozen_check: false,
                stale_after_ns: None,
                trust_rank: 2,
                // Speed over ground has no sign.
                signed: false,
                ..SourceConfig::default()
            },
            other: SourceConfig {
                command_check: false,
                frozen_check: false,
                stale_after_ns: None,
                trust_rank: 0,
                ..SourceConfig::default()
            },
        }
    }
}

impl SourceTable {
    /// Settings for one source.
    pub fn get(&self, s: FeedbackSource) -> &SourceConfig {
        match s {
            FeedbackSource::WheelOdometry => &self.wheel_odometry,
            FeedbackSource::Imu => &self.imu,
            FeedbackSource::JointState => &self.joint_state,
            FeedbackSource::Gnss => &self.gnss,
            FeedbackSource::Other => &self.other,
        }
    }
}

/// Full monitor configuration for one robot model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorConfig {
    /// Model label (for humans; matches the profile's `model`).
    pub model: String,
    /// Command channels to correlate (the *final* command after any mux).
    /// Empty = accept every channel.
    pub command_channels: Vec<String>,
    /// Command history capacity. Must cover `latency_max_ns` at the highest
    /// command rate (e.g. 100 Hz x 150 ms = 15; default 128).
    pub command_capacity: usize,
    /// Actuation latency window (dead time from command observed to motion
    /// starting, *plus* feedback transport delay), on the observer clock.
    pub latency_min_ns: u64,
    pub latency_max_ns: u64,
    /// Mirror of the platform's command watchdog: a command older than this
    /// counts as "rest". `None` = commands hold forever.
    pub command_timeout_ns: Option<u64>,
    /// Force magnitude comparison everywhere (legacy behaviour). Default
    /// `false`: values are signed body-frame velocities and a robot moving
    /// against its command is reported. Magnitude-only inputs are handled
    /// without this switch (`CommandSample::direction_known = false`,
    /// `SourceConfig::signed = false`). Setting it `true` makes direction
    /// reversals undetectable.
    pub compare_magnitudes: bool,
    /// The integrator feeds `set_safety_stop`. When `true`, a robot that
    /// moves less than commanded without a declared stop is `High`;
    /// otherwise it is `Medium` (could be an e-stop we were not told about).
    pub safety_stop_signal_wired: bool,
    /// After a safety stop is asserted, uncommanded-motion checks wait this
    /// long (coast-down); after release, under-motion checks wait this long
    /// (drive re-enable).
    pub safety_stop_grace_ns: u64,
    /// No command-model checks for this long after the first event (initial
    /// robot state unknown).
    pub warmup_ns: u64,
    /// A command axis at or below this magnitude counts as "rest".
    pub rest_command_eps: f64,
    pub linear: AxisModel,
    pub angular: AxisModel,
    pub joint: AxisModel,
    pub divergence: Persistence,
    pub uncommanded: Persistence,
    pub cross_sensor: Persistence,
    /// Two sources are compared only if their latest readings were received
    /// within this window of each other.
    pub cross_max_skew_ns: u64,
    /// Frozen-feedback: identical consecutive samples while moving.
    pub frozen_min_samples: u32,
    pub frozen_min_duration_ns: u64,
    /// Stamp more than this ahead of the observer clock = "future".
    pub max_future_skew_ns: u64,
    /// Stamp more than this behind the observer clock = "late" (replay with
    /// original stamps). `None` disables.
    pub max_stamp_age_ns: Option<u64>,
    /// Clean samples needed to re-arm a latched integrity finding.
    pub rearm_clean_samples: u32,
    /// A feedback publisher silent for longer than this no longer counts as
    /// active, and its state slot may be reused by a new publisher.
    pub publisher_expiry_ns: u64,
    /// Fraction (0, 1] of non-finite values among a source's last 64
    /// samples on an axis that escalates `invalid_feedback` to High while
    /// motion is expected or observed.
    pub nan_rate_high: f64,
    /// Samples (1..=64) the NaN-rate window must hold before it is judged.
    pub nan_rate_min_samples: u32,
    /// Hold for the command-model episodes (uncommanded motion,
    /// divergence): a good sample within this long (observer clock) of the
    /// latest bad sample of an open episode is neutral, neither diluting it
    /// nor counting toward `clear_samples`. Episodes are then judged on the
    /// stream's worst sample per hold window, so interleaving any number of
    /// plausible values between real ones (any ratio, any level) cannot hide
    /// a real excursion. Must exceed the slowest honest feedback period;
    /// neutral samples never count as bad, so sparse honest outliers are not
    /// amplified. `0` disables (per-sample majority, as before).
    pub episode_hold_ns: u64,
    /// Implausible-jump check on each (source, publisher) stream: two
    /// consecutive finite samples whose difference exceeds the cross-sensor
    /// tolerance **and** `jump_accel_factor * max_accel * dt` (dt = the larger
    /// of the stamp and arrival gaps) imply an acceleration the platform
    /// cannot produce. One such jump is a bump; many in a row are two
    /// streams interleaved on one topic (an injected publisher the caller
    /// could not attribute) or a corrupted driver. Must be >= 1. Axes with
    /// `max_accel = None` are not checked.
    pub jump_accel_factor: f64,
    /// Implausible jumps within one episode that raise
    /// `robot.motion.inconsistent_feedback_stream`. `0` disables the check.
    pub jump_min_count: u32,
    /// An episode of implausible jumps ends (and the check re-arms) after
    /// this long without one. Good samples in between do not end it, so an
    /// injector cannot hide behind many "at rest" samples per real one.
    pub jump_window_ns: u64,
    pub sources: SourceTable,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            model: String::from("generic-ugv"),
            command_channels: Vec::new(),
            command_capacity: 128,
            latency_min_ns: 20 * MS,
            latency_max_ns: 150 * MS,
            command_timeout_ns: Some(500 * MS),
            compare_magnitudes: false,
            safety_stop_signal_wired: false,
            safety_stop_grace_ns: 3_000 * MS,
            warmup_ns: 2_000 * MS,
            rest_command_eps: 1e-3,
            linear: AxisModel::default(),
            angular: AxisModel::ugv_angular(),
            joint: AxisModel::disabled(),
            divergence: Persistence::default(),
            uncommanded: Persistence {
                min_duration_ns: 300 * MS,
                min_samples: 5,
                min_bad_fraction: DEFAULT_BAD_FRACTION,
                clear_samples: 10,
            },
            cross_sensor: Persistence {
                min_duration_ns: 1_000 * MS,
                min_samples: 10,
                min_bad_fraction: DEFAULT_BAD_FRACTION,
                clear_samples: 10,
            },
            cross_max_skew_ns: 100 * MS,
            frozen_min_samples: 20,
            frozen_min_duration_ns: 500 * MS,
            max_future_skew_ns: 50 * MS,
            max_stamp_age_ns: Some(1_000 * MS),
            rearm_clean_samples: 10,
            publisher_expiry_ns: 2_000 * MS,
            nan_rate_high: 0.1,
            nan_rate_min_samples: 16,
            episode_hold_ns: 200 * MS,
            jump_accel_factor: 10.0,
            jump_min_count: 10,
            jump_window_ns: 1_000 * MS,
            sources: SourceTable::default(),
        }
    }
}

impl MonitorConfig {
    /// Starting point for a wheeled/tracked UGV.
    pub fn ugv(model: impl Into<String>) -> Self {
        MonitorConfig {
            model: model.into(),
            ..MonitorConfig::default()
        }
    }

    /// Starting point for a manipulator arm: joint axis only, tighter
    /// latencies, joint state as the primary feedback.
    pub fn manipulator(model: impl Into<String>) -> Self {
        MonitorConfig {
            model: model.into(),
            latency_min_ns: 2 * MS,
            latency_max_ns: 50 * MS,
            command_timeout_ns: Some(100 * MS),
            linear: AxisModel::disabled(),
            angular: AxisModel::disabled(),
            joint: AxisModel::manipulator_joint(),
            divergence: Persistence {
                min_duration_ns: 200 * MS,
                min_samples: 20,
                min_bad_fraction: DEFAULT_BAD_FRACTION,
                clear_samples: 20,
            },
            uncommanded: Persistence {
                min_duration_ns: 100 * MS,
                min_samples: 10,
                min_bad_fraction: DEFAULT_BAD_FRACTION,
                clear_samples: 20,
            },
            frozen_min_samples: 50,
            frozen_min_duration_ns: 200 * MS,
            warmup_ns: 500 * MS,
            ..MonitorConfig::default()
        }
    }

    /// Model for one axis.
    pub fn axis(&self, a: Axis) -> &AxisModel {
        match a {
            Axis::Linear => &self.linear,
            Axis::Angular => &self.angular,
            Axis::Joint => &self.joint,
        }
    }

    /// Reject configurations that would make the detector meaningless or
    /// misbehave (non-finite or negative parameters, empty windows).
    pub fn validate(&self) -> Result<(), ConfigError> {
        fn nonneg(name: &'static str, v: f64) -> Result<(), ConfigError> {
            if !v.is_finite() {
                Err(ConfigError::NonFinite(name))
            } else if v < 0.0 {
                Err(ConfigError::Negative(name))
            } else {
                Ok(())
            }
        }
        fn fraction(name: &'static str, v: f64) -> Result<(), ConfigError> {
            nonneg(name, v)?;
            if v == 0.0 || v > 1.0 {
                Err(ConfigError::Fraction(name))
            } else {
                Ok(())
            }
        }
        for a in Axis::ALL {
            let m = self.axis(a);
            nonneg("tau_s", m.tau_s)?;
            if let Some(acc) = m.max_accel {
                nonneg("max_accel", acc)?;
                if acc == 0.0 {
                    return Err(ConfigError::Zero("max_accel"));
                }
            }
            nonneg("abs_tol", m.abs_tol)?;
            nonneg("rel_tol", m.rel_tol)?;
            nonneg("still_threshold", m.still_threshold)?;
            nonneg("uncommanded_critical", m.uncommanded_critical)?;
            nonneg("cross_abs_tol", m.cross_abs_tol)?;
            nonneg("cross_rel_tol", m.cross_rel_tol)?;
        }
        nonneg("rest_command_eps", self.rest_command_eps)?;
        if self.latency_min_ns > self.latency_max_ns {
            return Err(ConfigError::LatencyWindow);
        }
        if !(2..=65_536).contains(&self.command_capacity) {
            return Err(ConfigError::Capacity(self.command_capacity));
        }
        for (name, p) in [
            ("divergence", &self.divergence),
            ("uncommanded", &self.uncommanded),
            ("cross_sensor", &self.cross_sensor),
        ] {
            if p.min_samples == 0 || p.clear_samples == 0 {
                return Err(ConfigError::Zero(name));
            }
            fraction("min_bad_fraction", p.min_bad_fraction)?;
        }
        fraction("nan_rate_high", self.nan_rate_high)?;
        if !(1..=64).contains(&self.nan_rate_min_samples) {
            return Err(ConfigError::Range("nan_rate_min_samples"));
        }
        nonneg("jump_accel_factor", self.jump_accel_factor)?;
        if self.jump_accel_factor < 1.0 {
            return Err(ConfigError::Range("jump_accel_factor"));
        }
        if self.jump_window_ns == 0 {
            return Err(ConfigError::Zero("jump_window_ns"));
        }
        if self.publisher_expiry_ns == 0 {
            return Err(ConfigError::Zero("publisher_expiry_ns"));
        }
        if self.frozen_min_samples == 0 {
            return Err(ConfigError::Zero("frozen_min_samples"));
        }
        if self.rearm_clean_samples == 0 {
            return Err(ConfigError::Zero("rearm_clean_samples"));
        }
        Ok(())
    }
}

/// Why a configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NonFinite(&'static str),
    Negative(&'static str),
    Zero(&'static str),
    LatencyWindow,
    Capacity(usize),
    /// A fraction outside (0, 1].
    Fraction(&'static str),
    /// A parameter outside its documented range.
    Range(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NonFinite(n) => write!(f, "parameter {n} is not finite"),
            ConfigError::Negative(n) => write!(f, "parameter {n} is negative"),
            ConfigError::Zero(n) => write!(f, "parameter {n} must be non-zero"),
            ConfigError::LatencyWindow => write!(f, "latency_min_ns > latency_max_ns"),
            ConfigError::Fraction(n) => write!(f, "parameter {n} must be in (0, 1]"),
            ConfigError::Range(n) => write!(f, "parameter {n} is outside its valid range"),
            ConfigError::Capacity(c) => {
                write!(f, "command_capacity {c} outside 2..=65536")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // one mutation per case reads clearer
mod tests {
    use super::*;

    #[test]
    fn presets_validate() {
        MonitorConfig::default().validate().unwrap();
        MonitorConfig::ugv("jackal").validate().unwrap();
        MonitorConfig::manipulator("fr3").validate().unwrap();
    }

    #[test]
    fn rejects_bad_values() {
        let mut c = MonitorConfig::default();
        c.linear.tau_s = f64::NAN;
        assert_eq!(c.validate(), Err(ConfigError::NonFinite("tau_s")));

        let mut c = MonitorConfig::default();
        c.angular.abs_tol = -0.1;
        assert_eq!(c.validate(), Err(ConfigError::Negative("abs_tol")));

        let mut c = MonitorConfig::default();
        c.linear.max_accel = Some(f64::INFINITY);
        assert_eq!(c.validate(), Err(ConfigError::NonFinite("max_accel")));

        let mut c = MonitorConfig::default();
        c.linear.max_accel = Some(0.0);
        assert_eq!(c.validate(), Err(ConfigError::Zero("max_accel")));

        let mut c = MonitorConfig::default();
        c.latency_min_ns = c.latency_max_ns + 1;
        assert_eq!(c.validate(), Err(ConfigError::LatencyWindow));

        let mut c = MonitorConfig::default();
        c.command_capacity = 1;
        assert_eq!(c.validate(), Err(ConfigError::Capacity(1)));

        let mut c = MonitorConfig::default();
        c.uncommanded.min_samples = 0;
        assert_eq!(c.validate(), Err(ConfigError::Zero("uncommanded")));

        let mut c = MonitorConfig::default();
        c.divergence.min_bad_fraction = 0.0;
        assert_eq!(c.validate(), Err(ConfigError::Fraction("min_bad_fraction")));
        c.divergence.min_bad_fraction = 1.5;
        assert_eq!(c.validate(), Err(ConfigError::Fraction("min_bad_fraction")));
        c.divergence.min_bad_fraction = f64::NAN;
        assert_eq!(
            c.validate(),
            Err(ConfigError::NonFinite("min_bad_fraction"))
        );

        let mut c = MonitorConfig::default();
        c.nan_rate_high = 0.0;
        assert_eq!(c.validate(), Err(ConfigError::Fraction("nan_rate_high")));

        let mut c = MonitorConfig::default();
        c.nan_rate_min_samples = 65;
        assert_eq!(
            c.validate(),
            Err(ConfigError::Range("nan_rate_min_samples"))
        );

        let mut c = MonitorConfig::default();
        c.jump_accel_factor = 0.5;
        assert_eq!(c.validate(), Err(ConfigError::Range("jump_accel_factor")));
        c.jump_accel_factor = f64::INFINITY;
        assert_eq!(
            c.validate(),
            Err(ConfigError::NonFinite("jump_accel_factor"))
        );
        let mut c = MonitorConfig::default();
        c.jump_window_ns = 0;
        assert_eq!(c.validate(), Err(ConfigError::Zero("jump_window_ns")));
        let mut c = MonitorConfig::default();
        c.jump_min_count = 0; // disables the check: valid
        assert_eq!(c.validate(), Ok(()));

        let mut c = MonitorConfig::default();
        c.publisher_expiry_ns = 0;
        assert_eq!(c.validate(), Err(ConfigError::Zero("publisher_expiry_ns")));

        let mut c = MonitorConfig::default();
        c.rest_command_eps = f64::NEG_INFINITY;
        assert!(c.validate().is_err());
        assert!(!c.validate().unwrap_err().to_string().is_empty());
    }

    #[test]
    fn json_roundtrip_and_partial_config() {
        let c = MonitorConfig::manipulator("fr3");
        let j = serde_json::to_string(&c).unwrap();
        let back: MonitorConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);

        // Missing fields fall back to defaults.
        let partial: MonitorConfig =
            serde_json::from_str(r#"{"model":"x","latency_max_ns":200000000}"#).unwrap();
        assert_eq!(partial.model, "x");
        assert_eq!(partial.latency_max_ns, 200 * MS);
        assert_eq!(partial.linear, AxisModel::default());
        partial.validate().unwrap();
    }

    #[test]
    fn source_table_lookup() {
        let t = SourceTable::default();
        assert_eq!(t.get(FeedbackSource::Imu).trust_rank, 3);
        assert!(!t.get(FeedbackSource::Gnss).command_check);
        assert!(!t.get(FeedbackSource::Gnss).signed);
        assert!(t.get(FeedbackSource::WheelOdometry).signed && t.get(FeedbackSource::Imu).signed);
        assert!(
            !MonitorConfig::default().compare_magnitudes,
            "direction checks on by default"
        );
        assert!(t.get(FeedbackSource::Imu).trust_rank > t.get(FeedbackSource::Gnss).trust_rank);
        assert!(
            t.get(FeedbackSource::Gnss).trust_rank
                > t.get(FeedbackSource::WheelOdometry).trust_rank
        );
    }
}
