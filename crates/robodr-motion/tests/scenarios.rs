//! Synthetic-trace scenarios. A simple plant (dead time + rate-limited first
//! order, with parameters deliberately *different* from the monitor's model)
//! is driven by a command profile; sensor closures turn the true motion into
//! feedback, honestly or not. These are synthetic: they show the logic
//! behaves as designed, not that the thresholds fit real hardware.

use robodr_events::{MotionCommand, Severity};
use robodr_motion::*;

const MS: u64 = 1_000_000;
/// Observer clock starts at 1 s so stamps slightly behind it stay positive.
const T0: u64 = 1_000 * MS;

#[derive(Clone, Copy, Default, Debug)]
struct Truth {
    lin: f64,
    ang: f64,
}

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Approximately normal, std `sigma`.
    fn gauss(&mut self, sigma: f64) -> f64 {
        let s: f64 = (0..4).map(|_| self.unit()).sum::<f64>() - 2.0;
        s / 0.577_350_269 * sigma
    }
}

#[derive(Clone, Copy)]
struct Plant {
    lat_ms: u64,
    tau: f64,
    acc: f64,
    watchdog_ms: Option<u64>,
}

impl Default for Plant {
    fn default() -> Self {
        // Slower tau and different latency than the monitor's defaults
        // (tau 0.25 / 0.20, latency 20-150 ms).
        Plant {
            lat_ms: 80,
            tau: 0.30,
            acc: 1.8,
            watchdog_ms: Some(500),
        }
    }
}

type Cmd = Option<(Option<f64>, Option<f64>)>;
/// (t, ideal response to commands, actual motion, rng, out).
type SensorFn = dyn Fn(f64, Truth, Truth, &mut Rng, &mut Vec<FeedbackSample>);

struct World<'a> {
    /// Called every `cmd_period_ms`; `None` = nothing published.
    command: &'a dyn Fn(f64) -> Cmd,
    /// Maps the input the plant *would* follow (delayed command) to the input
    /// it actually follows (e-stop, stuck robot, injected command).
    actuate: &'a dyn Fn(f64, Truth) -> Truth,
    /// Turns (t, ideal response to commands, actual motion) into feedback.
    sensors: &'a SensorFn,
    safety_stop: &'a dyn Fn(f64) -> bool,
    plant: Plant,
    cmd_period_ms: u64,
    fb_period_ms: u64,
    channel: &'a str,
}

fn no_change(_: f64, u: Truth) -> Truth {
    u
}
fn never(_: f64) -> bool {
    false
}

/// Honest wheel odometry (linear + angular) and IMU gyro (angular), 1 cm/s
/// and 0.01 rad/s noise.
fn honest(t: f64, _ideal: Truth, actual: Truth, rng: &mut Rng, out: &mut Vec<FeedbackSample>) {
    out.push(fb(
        t,
        FeedbackSource::WheelOdometry,
        Some(actual.lin + rng.gauss(0.01)),
        Some(actual.ang + rng.gauss(0.01)),
    ));
    out.push(fb(
        t,
        FeedbackSource::Imu,
        None,
        Some(actual.ang + rng.gauss(0.01)),
    ));
}

fn fb(
    t_s: f64,
    source: FeedbackSource,
    linear: Option<f64>,
    angular: Option<f64>,
) -> FeedbackSample {
    FeedbackSample {
        t_ns: ns(t_s).saturating_sub(2 * MS),
        source,
        linear,
        angular,
        joint_speed_max: None,
    }
}

fn ns(t_s: f64) -> u64 {
    T0 + (t_s * 1e9).round() as u64
}

impl<'a> World<'a> {
    fn new(command: &'a dyn Fn(f64) -> Cmd) -> Self {
        World {
            command,
            actuate: &no_change,
            sensors: &honest,
            safety_stop: &never,
            plant: Plant::default(),
            cmd_period_ms: 50,
            fb_period_ms: 20,
            channel: "/cmd_vel",
        }
    }

    fn run(&self, cfg: MonitorConfig, dur_s: f64) -> (Vec<Finding>, ConsistencyMonitor) {
        let mut mon = ConsistencyMonitor::new(cfg).unwrap();
        let mut findings = Vec::new();
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut hist: Vec<(u64, f64, f64)> = Vec::new();
        let (mut ideal, mut actual) = (Truth::default(), Truth::default());
        let mut stop = false;
        let mut buf = Vec::new();
        let steps = (dur_s * 1000.0) as u64;
        let p = self.plant;
        for k in 0..=steps {
            let t_s = k as f64 / 1000.0;
            let now = ns(t_s);
            let want_stop = (self.safety_stop)(t_s);
            if want_stop != stop {
                stop = want_stop;
                mon.set_safety_stop(now, stop);
            }
            if k % self.cmd_period_ms == 0 {
                if let Some((lin, ang)) = (self.command)(t_s) {
                    hist.push((now, lin.unwrap_or(0.0), ang.unwrap_or(0.0)));
                    let c = CommandSample {
                        t_ns: now,
                        channel: self.channel,
                        linear: lin,
                        angular: ang,
                        joint_speed_max: None,
                        direction_known: true,
                    };
                    mon.on_command(&c, |f| findings.push(f));
                }
            }
            // Plant: delayed command, platform watchdog, then dynamics.
            let at = now.saturating_sub(p.lat_ms * MS);
            let mut u = Truth::default();
            if let Some(&(tc, l, a)) = hist.iter().rev().find(|(tc, _, _)| *tc <= at) {
                let alive = p.watchdog_ms.is_none_or(|w| at - tc <= w * MS);
                if alive {
                    u = Truth { lin: l, ang: a };
                }
            }
            let ua = (self.actuate)(t_s, u);
            let dt = 0.001;
            ideal.lin = first_order_step(ideal.lin, u.lin, dt, p.tau, Some(p.acc));
            ideal.ang = first_order_step(ideal.ang, u.ang, dt, p.tau, Some(p.acc * 2.0));
            actual.lin = first_order_step(actual.lin, ua.lin, dt, p.tau, Some(p.acc));
            actual.ang = first_order_step(actual.ang, ua.ang, dt, p.tau, Some(p.acc * 2.0));
            if k % self.fb_period_ms == 0 {
                buf.clear();
                (self.sensors)(t_s, ideal, actual, &mut rng, &mut buf);
                for s in &buf {
                    mon.on_feedback(now, s, |f| findings.push(f));
                }
            }
            if k % 100 == 0 {
                mon.tick(now, |f| findings.push(f));
            }
        }
        (findings, mon)
    }
}

/// A busy healthy profile: warm-up at rest, steps, reversal in yaw, stop,
/// restart, ramp.
fn busy_profile(t: f64) -> Cmd {
    let (l, a) = if t < 3.0 {
        (0.0, 0.0)
    } else if t < 8.0 {
        (1.0, 0.3)
    } else if t < 12.0 {
        (0.5, -0.4)
    } else if t < 15.0 {
        (0.0, 0.0)
    } else if t < 18.0 {
        (1.2, 0.0)
    } else {
        ((20.0 - t) * 0.5, 0.0) // ramp down
    };
    Some((Some(l), Some(a)))
}

fn rules_of(f: &[Finding]) -> Vec<&'static str> {
    f.iter().map(|x| x.rule).collect()
}

fn ugv() -> MonitorConfig {
    MonitorConfig {
        command_channels: vec!["/cmd_vel".into()],
        ..MonitorConfig::ugv("test-ugv")
    }
}

fn first(f: &[Finding], rule: &str) -> Finding {
    *f.iter()
        .find(|x| x.rule == rule)
        .unwrap_or_else(|| panic!("no {rule} in {:?}", rules_of(f)))
}

// ------------------------------------------------------------ healthy cases

#[test]
fn healthy_tracking_with_lag_raises_nothing() {
    let w = World::new(&busy_profile);
    let (f, mon) = w.run(ugv(), 22.0);
    assert!(f.is_empty(), "false positives: {f:#?}");
    let s = mon.stats();
    assert!(s.commands > 400 && s.feedback > 2000);
    assert_eq!(s.history_underruns, 0);
    assert_eq!(s.commands_ignored, 0);
}

#[test]
fn healthy_at_both_ends_of_latency_window() {
    for lat_ms in [20, 60, 145] {
        for tau in [0.15, 0.25, 0.35] {
            let mut w = World::new(&busy_profile);
            w.plant = Plant {
                lat_ms,
                tau,
                ..Plant::default()
            };
            let (f, _) = w.run(ugv(), 22.0);
            assert!(f.is_empty(), "lat {lat_ms} ms tau {tau}: {f:#?}");
        }
    }
}

#[test]
fn step_change_within_latency_raises_nothing() {
    // A hard 0 -> 1.5 m/s step, robot responds at the slow end of the window.
    let step = |t: f64| Some((Some(if t < 4.0 { 0.0 } else { 1.5 }), Some(0.0)));
    let mut w = World::new(&step);
    w.plant = Plant {
        lat_ms: 148,
        ..Plant::default()
    };
    let (f, _) = w.run(ugv(), 8.0);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn wheel_slip_short_transient_raises_nothing() {
    // Wheels spin on a wet patch for 250 ms: odometry over-reports linear and
    // one-sided slip shows as yaw rate the gyro does not see.
    let sensors = |t: f64, i: Truth, a: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
        honest(t, i, a, r, out);
        if (8.0..8.25).contains(&t) {
            out[0].linear = Some(a.lin + 0.9);
            out[0].angular = Some(a.ang + 0.6);
        }
    };
    let mut w = World::new(&busy_profile);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 22.0);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn stationary_identical_zeros_are_not_frozen() {
    // Noise-free drivers publish exact zeros at rest: legitimate.
    let sensors = |t: f64, _: Truth, _: Truth, _: &mut Rng, out: &mut Vec<FeedbackSample>| {
        out.push(fb(t, FeedbackSource::WheelOdometry, Some(0.0), Some(0.0)));
        out.push(fb(t, FeedbackSource::Imu, None, Some(0.0)));
    };
    let zero = |_: f64| Some((Some(0.0), Some(0.0)));
    let mut w = World::new(&zero);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn command_publisher_dies_and_watchdog_stops_robot_raises_nothing() {
    // Planner crashes at 6 s; the base controller's watchdog stops the
    // robot. The monitor mirrors the watchdog, so this is expected.
    let cmd = |t: f64| (t < 6.0).then_some((Some(if t < 3.0 { 0.0 } else { 1.0 }), Some(0.0)));
    let w = World::new(&cmd);
    let (f, _) = w.run(ugv(), 10.0);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn unspecified_axis_is_not_judged() {
    // Commands from MotionCommand carry no yaw rate: turning is not judged
    // against the command (but the IMU still agrees with odometry).
    let mc = MotionCommand {
        channel: "/cmd_vel".into(),
        source_guid: None,
        linear_speed: Some(0.8),
        joint_speed: None,
        angular_speed: None,
    };
    let mut mon = ConsistencyMonitor::new(ugv()).unwrap();
    let mut f = Vec::new();
    for k in 0..400u64 {
        let now = T0 + k * 20 * MS;
        if k % 2 == 0 {
            mon.on_command(&CommandSample::from((&mc, now)), |x| f.push(x));
        }
        let lin = if k < 10 { 0.0 } else { 0.8 };
        let s = FeedbackSample {
            t_ns: now,
            source: FeedbackSource::WheelOdometry,
            linear: Some(lin + (k % 3) as f64 * 0.001),
            angular: Some(0.7 + (k % 5) as f64 * 0.001),
            joint_speed_max: None,
        };
        mon.on_feedback(now, &s, |x| f.push(x));
    }
    assert!(mon.expected_band(Axis::Angular).is_none());
    let band = mon.expected_band(Axis::Linear).unwrap();
    assert!((band.0 - 0.8).abs() < 1e-6 && (band.1 - 0.8).abs() < 1e-6);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn other_channels_are_ignored() {
    let w = World {
        channel: "/cmd_vel_teleop_raw",
        ..World::new(&busy_profile)
    };
    let (f, mon) = w.run(ugv(), 5.0);
    assert!(mon.stats().commands_ignored > 0);
    // The robot moves on commands we do not correlate: uncommanded.
    assert!(rules_of(&f).contains(&rules::UNCOMMANDED_MOTION));
}

// --------------------------------------------------------------- detections

#[test]
fn fake_odometry_mirroring_commands_while_imu_says_stationary() {
    // "Seeing is Not Believing": the robot is actually held still (or doing
    // something else) while a hooked controller publishes odometry that
    // mirrors the command perfectly. Only the gyro tells the truth.
    let held = |_: f64, _: Truth| Truth::default();
    let sensors =
        |_t: f64, ideal: Truth, actual: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
            out.push(fb(
                _t,
                FeedbackSource::WheelOdometry,
                Some(ideal.lin + r.gauss(0.01)),
                Some(ideal.ang + r.gauss(0.01)),
            ));
            out.push(fb(
                _t,
                FeedbackSource::Imu,
                None,
                Some(actual.ang + r.gauss(0.01)),
            ));
        };
    let mut w = World::new(&busy_profile);
    w.actuate = &held;
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);

    // Fake odometry passes the command check by construction...
    assert!(!f.iter().any(|x| x.rule == rules::FEEDBACK_DIVERGENCE
        && matches!(
            x.evidence,
            Evidence::FeedbackDivergence {
                source: FeedbackSource::WheelOdometry,
                ..
            }
        )));
    // ...but cannot fool the IMU.
    let c = first(&f, rules::CROSS_SENSOR_DISAGREEMENT);
    assert_eq!(c.severity, Severity::High);
    match c.evidence {
        Evidence::CrossSensorDisagreement {
            axis,
            source_a,
            source_b,
            more_trusted,
            value_a,
            value_b,
            ..
        } => {
            assert_eq!(axis, Axis::Angular);
            assert_eq!(
                (source_a, source_b),
                (FeedbackSource::WheelOdometry, FeedbackSource::Imu)
            );
            assert_eq!(more_trusted, Some(FeedbackSource::Imu));
            assert!(value_a > 0.2 && value_b.abs() < 0.05);
        }
        e => panic!("{e:?}"),
    }
    // Detected within ~1.5 s of motion being commanded (3 s) and settling.
    assert!(c.t_ns < ns(5.0), "late: {}", c.t_ns);
    // The IMU itself diverges from the command (under-motion; Medium because
    // the safety-stop signal is not wired in this config).
    let d = f
        .iter()
        .find(|x| {
            matches!(
                x.evidence,
                Evidence::FeedbackDivergence {
                    source: FeedbackSource::Imu,
                    direction: Direction::Under,
                    ..
                }
            )
        })
        .expect("imu under-motion");
    assert_eq!(d.severity, Severity::Medium);
    let dev = c.to_deviation();
    assert_eq!(dev.rule, "robot.motion.cross_sensor_disagreement");
    assert!(
        dev.detail.contains("imu is the more trusted source"),
        "{}",
        dev.detail
    );
}

#[test]
fn gnss_spoof_is_the_odd_one_out() {
    // Odometry and a fused IMU velocity agree; spoofed GNSS reports 2.5 m/s.
    let sensors = |t: f64, i: Truth, a: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
        honest(t, i, a, r, out);
        out[1].linear = Some(a.lin + r.gauss(0.02));
        if t > 5.0 {
            out.push(fb(t, FeedbackSource::Gnss, Some(2.5 + r.gauss(0.05)), None));
        } else {
            out.push(fb(
                t,
                FeedbackSource::Gnss,
                Some(a.lin + r.gauss(0.05)),
                None,
            ));
        }
    };
    let mut w = World::new(&busy_profile);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);
    let pairs: Vec<_> = f
        .iter()
        .filter_map(|x| match x.evidence {
            Evidence::CrossSensorDisagreement {
                source_a,
                source_b,
                axis,
                ..
            } => Some((source_a, source_b, axis)),
            _ => None,
        })
        .collect();
    assert!(pairs.contains(&(
        FeedbackSource::WheelOdometry,
        FeedbackSource::Gnss,
        Axis::Linear
    )));
    assert!(pairs.contains(&(FeedbackSource::Imu, FeedbackSource::Gnss, Axis::Linear)));
    assert!(!pairs
        .iter()
        .any(|p| p.0 == FeedbackSource::WheelOdometry && p.1 == FeedbackSource::Imu));
    // GNSS is not command-checked by default: no divergence attributed to it.
    assert!(!f.iter().any(|x| x.rule == rules::FEEDBACK_DIVERGENCE));
}

#[test]
fn frozen_feedback_while_moving_is_detected() {
    // At 6 s the odometry stream freezes on its last value (replayed /
    // stuck publisher) while the robot keeps driving at 1 m/s. The frozen
    // value is still inside the band, so only the frozen check sees it.
    let sensors = |t: f64, i: Truth, a: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
        honest(t, i, a, r, out);
        if t >= 6.0 {
            out[0].linear = Some(0.987_654);
            out[0].angular = Some(0.301_234);
        }
    };
    let cmd = |t: f64| {
        Some((
            Some(if t < 3.0 { 0.0 } else { 1.0 }),
            Some(if t < 3.0 { 0.0 } else { 0.3 }),
        ))
    };
    let mut w = World::new(&cmd);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);
    let fr = first(&f, rules::FROZEN_FEEDBACK);
    assert_eq!(fr.severity, Severity::High);
    match fr.evidence {
        Evidence::FrozenValues {
            source, repeats, ..
        } => {
            assert_eq!(source, FeedbackSource::WheelOdometry);
            assert!(repeats >= 20);
        }
        e => panic!("{e:?}"),
    }
    assert!(fr.t_ns >= ns(6.5) && fr.t_ns < ns(7.0));
    assert_eq!(
        f.iter()
            .filter(|x| x.rule == rules::FROZEN_FEEDBACK)
            .count(),
        1,
        "latched"
    );
}

#[test]
fn stale_feedback_while_moving_is_detected() {
    let sensors = |t: f64, i: Truth, a: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
        honest(t, i, a, r, out);
        if t >= 6.0 {
            out.remove(0); // odometry goes silent
        }
    };
    let cmd = |t: f64| Some((Some(if t < 3.0 { 0.0 } else { 1.0 }), Some(0.0)));
    let mut w = World::new(&cmd);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);
    let s = first(&f, rules::FROZEN_FEEDBACK);
    assert_eq!(s.severity, Severity::Medium);
    assert!(matches!(
        s.evidence,
        Evidence::StaleFeedback {
            source: FeedbackSource::WheelOdometry,
            ..
        }
    ));
    assert_eq!(f.len(), 1, "{f:#?}");
}

#[test]
fn replayed_timestamps_are_detected() {
    // At 6 s an attacker loops a recorded odometry clip: stamps jump back
    // 2 s and the values come from the recording.
    let sensors = |t: f64, i: Truth, a: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
        honest(t, i, a, r, out);
        if t >= 6.0 {
            out[0].t_ns -= 2_000 * MS;
        }
    };
    let mut w = World::new(&busy_profile);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);
    let stamps: Vec<_> = f
        .iter()
        .filter_map(|x| match x.evidence {
            Evidence::TimestampAnomaly {
                anomaly, source, ..
            } => Some((anomaly, source, x.severity)),
            _ => None,
        })
        .collect();
    assert_eq!(
        stamps,
        vec![
            // The jump back when the loop starts...
            (
                StampAnomaly::Backwards,
                FeedbackSource::WheelOdometry,
                Severity::High
            ),
            // ...and every replayed stamp is 2 s old on arrival.
            (
                StampAnomaly::Late,
                FeedbackSource::WheelOdometry,
                Severity::Medium
            ),
        ],
        "{f:#?}"
    );
    // Latched: one finding per anomaly kind, not one per sample.
    assert_eq!(f.len(), 2, "{f:#?}");
}

#[test]
fn stamp_anomalies_each_kind() {
    let mut mon = ConsistencyMonitor::new(ugv()).unwrap();
    let mut f = Vec::new();
    let s = |t_ns| FeedbackSample {
        t_ns,
        source: FeedbackSource::Imu,
        linear: None,
        angular: Some(0.0),
        joint_speed_max: None,
    };
    let now = 10_000 * MS;
    mon.on_feedback(now, &s(now - MS), |x| f.push(x));
    assert!(f.is_empty());
    mon.on_feedback(now + 10 * MS, &s(now - MS), |x| f.push(x)); // duplicate
    mon.on_feedback(now + 20 * MS, &s(now + 5_000 * MS), |x| f.push(x)); // future
    mon.on_feedback(now + 30 * MS, &s(now + 10 * MS), |x| f.push(x)); // backwards
    mon.on_feedback(now + 40 * MS, &s(now - 5_000 * MS), |x| f.push(x)); // backwards again: latched
    mon.on_feedback(now + 50 * MS, &s(now - 4_000 * MS), |x| f.push(x)); // late
    let kinds: Vec<_> = f
        .iter()
        .map(|x| match x.evidence {
            Evidence::TimestampAnomaly { anomaly, .. } => (anomaly, x.severity),
            e => panic!("{e:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (StampAnomaly::Duplicate, Severity::Medium),
            (StampAnomaly::Future, Severity::High),
            (StampAnomaly::Backwards, Severity::High),
            (StampAnomaly::Late, Severity::Medium),
        ]
    );
    assert!(f.iter().all(|x| x.rule == rules::FROZEN_FEEDBACK));
    assert_eq!(mon.stats().duplicates_skipped, 1);
}

#[test]
fn uncommanded_motion_fast_is_critical() {
    // The observed /cmd_vel says stop; something else drives the robot at
    // 0.6 m/s from 4 s to 6 s.
    let inject = |t: f64, u: Truth| {
        if (4.0..6.0).contains(&t) {
            Truth { lin: 0.6, ang: 0.0 }
        } else {
            u
        }
    };
    let zero = |_: f64| Some((Some(0.0), Some(0.0)));
    let mut w = World::new(&zero);
    w.actuate = &inject;
    let (f, _) = w.run(ugv(), 8.0);
    let u = first(&f, rules::UNCOMMANDED_MOTION);
    assert_eq!(u.severity, Severity::Critical);
    assert!(u.t_ns < ns(5.0));
    match u.evidence {
        Evidence::UncommandedMotion {
            source,
            axis,
            measured,
            ..
        } => {
            assert_eq!(
                (source, axis),
                (FeedbackSource::WheelOdometry, Axis::Linear)
            );
            assert!(measured > 0.3);
        }
        e => panic!("{e:?}"),
    }
    assert_eq!(
        f.iter()
            .filter(|x| x.rule == rules::UNCOMMANDED_MOTION)
            .count(),
        1
    );
    assert!(
        !f.iter().any(|x| x.rule == rules::FEEDBACK_DIVERGENCE),
        "{f:#?}"
    );
}

#[test]
fn uncommanded_motion_slow_is_high_and_short_bump_is_ignored() {
    let creep = |t: f64, u: Truth| {
        if (4.0..7.0).contains(&t) {
            Truth {
                lin: 0.15,
                ang: 0.0,
            }
        } else {
            u
        }
    };
    let zero = |_: f64| Some((Some(0.0), Some(0.0)));
    let mut w = World::new(&zero);
    w.actuate = &creep;
    let (f, _) = w.run(ugv(), 9.0);
    assert_eq!(
        first(&f, rules::UNCOMMANDED_MOTION).severity,
        Severity::High
    );

    // An 80 ms kick (someone bumps the robot) stays under persistence. (On
    // this deliberately sluggish plant a 150 ms shove really does move the
    // robot above the band for > 300 ms, and is reported.)
    let bump = |t: f64, u: Truth| {
        if (4.0..4.08).contains(&t) {
            Truth { lin: 1.5, ang: 0.0 }
        } else {
            u
        }
    };
    let mut w = World::new(&zero);
    w.actuate = &bump;
    let (f, _) = w.run(ugv(), 9.0);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn uncommanded_with_no_commands_at_all() {
    let none = |_: f64| None;
    let inject = |t: f64, _: Truth| Truth {
        lin: 0.0,
        ang: if t > 3.0 { 0.8 } else { 0.0 },
    };
    let mut w = World::new(&none);
    w.actuate = &inject;
    let (f, _) = w.run(ugv(), 6.0);
    let u = first(&f, rules::UNCOMMANDED_MOTION);
    assert_eq!(u.severity, Severity::Critical);
    // Both odometry and the IMU see it.
    let srcs: Vec<_> = f
        .iter()
        .filter_map(|x| match x.evidence {
            Evidence::UncommandedMotion { source, .. } => Some(source),
            _ => None,
        })
        .collect();
    assert!(srcs.contains(&FeedbackSource::WheelOdometry) && srcs.contains(&FeedbackSource::Imu));
}

// ------------------------------------------------------------------ e-stop

fn estop_window(t: f64) -> bool {
    (8.0..12.0).contains(&t)
}
fn estop_actuate(t: f64, u: Truth) -> Truth {
    if estop_window(t) {
        Truth::default()
    } else {
        u
    }
}
/// Planner keeps publishing 1 m/s throughout; the platform e-stops 8-12 s.
fn keep_driving(t: f64) -> Cmd {
    Some((Some(if t < 3.0 { 0.0 } else { 1.0 }), Some(0.0)))
}

#[test]
fn estop_declared_raises_nothing() {
    let mut w = World::new(&keep_driving);
    w.actuate = &estop_actuate;
    w.safety_stop = &estop_window;
    let mut cfg = ugv();
    cfg.safety_stop_signal_wired = true;
    let (f, mon) = w.run(cfg, 18.0);
    assert!(f.is_empty(), "{f:#?}");
    assert!(!mon.safety_stop_active());
}

#[test]
fn estop_undeclared_unwired_is_medium_under_motion() {
    let mut w = World::new(&keep_driving);
    w.actuate = &estop_actuate;
    let (f, _) = w.run(ugv(), 14.0);
    assert!(!f.is_empty());
    for x in &f {
        assert_eq!(x.rule, rules::FEEDBACK_DIVERGENCE, "{x:?}");
        assert_eq!(x.severity, Severity::Medium);
        assert!(matches!(
            x.evidence,
            Evidence::FeedbackDivergence {
                direction: Direction::Under,
                axis: Axis::Linear,
                ..
            }
        ));
    }
    assert!(f[0].t_ns > ns(8.5) && f[0].t_ns < ns(9.5));
}

#[test]
fn estop_undeclared_but_signal_wired_is_high() {
    let mut w = World::new(&keep_driving);
    w.actuate = &estop_actuate;
    let mut cfg = ugv();
    cfg.safety_stop_signal_wired = true;
    let (f, _) = w.run(cfg, 14.0);
    assert_eq!(
        first(&f, rules::FEEDBACK_DIVERGENCE).severity,
        Severity::High
    );
}

#[test]
fn motion_during_declared_estop_after_grace_is_uncommanded() {
    // E-stop declared but the robot keeps going (the stop chain failed or
    // the motion is injected below it). After the coast-down grace this is
    // reported.
    let mut w = World::new(&keep_driving);
    w.safety_stop = &estop_window;
    let (f, _) = w.run(ugv(), 13.0);
    let u = first(&f, rules::UNCOMMANDED_MOTION);
    assert_eq!(u.severity, Severity::Critical);
    assert!(u.t_ns >= ns(11.0), "fired inside grace: {}", u.t_ns);
}

// ------------------------------------------------------- hostile / integrity

#[test]
fn non_finite_feedback_is_reported_once_then_escalated_while_moving() {
    // One second of NaN odometry / -inf gyro while driving: one Medium per
    // source/axis on the first bad value, then one High once the NaN rate
    // over the last 64 samples is high while the robot is moving (NaN
    // blinds every motion check). Nothing else fires.
    let sensors = |t: f64, i: Truth, a: Truth, r: &mut Rng, out: &mut Vec<FeedbackSample>| {
        honest(t, i, a, r, out);
        if (5.0..6.0).contains(&t) {
            out[0].linear = Some(f64::NAN);
            out[1].angular = Some(f64::NEG_INFINITY);
        }
    };
    let mut w = World::new(&busy_profile);
    w.sensors = &sensors;
    let (f, _) = w.run(ugv(), 10.0);
    let inv: Vec<_> = f
        .iter()
        .filter(|x| x.rule == rules::INVALID_FEEDBACK)
        .map(|x| (x.evidence, x.severity))
        .collect();
    assert_eq!(
        inv,
        vec![
            (
                Evidence::NonFiniteFeedback {
                    source: FeedbackSource::WheelOdometry,
                    axis: Axis::Linear
                },
                Severity::Medium
            ),
            (
                Evidence::NonFiniteFeedback {
                    source: FeedbackSource::Imu,
                    axis: Axis::Angular
                },
                Severity::Medium
            ),
            (
                Evidence::NonFiniteRate {
                    source: FeedbackSource::WheelOdometry,
                    axis: Axis::Linear,
                    invalid: 7,
                    window: 64
                },
                Severity::High
            ),
            (
                Evidence::NonFiniteRate {
                    source: FeedbackSource::Imu,
                    axis: Axis::Angular,
                    invalid: 7,
                    window: 64
                },
                Severity::High
            ),
        ]
    );
    assert_eq!(f.len(), 4, "{f:#?}");
}

#[test]
fn non_finite_and_huge_commands_do_not_panic() {
    let mut mon = ConsistencyMonitor::new(ugv()).unwrap();
    let mut n = 0;
    for (i, v) in [
        f64::NAN,
        f64::INFINITY,
        -f64::INFINITY,
        f64::MAX,
        -f64::MAX,
        1e308,
        -0.0,
    ]
    .into_iter()
    .enumerate()
    {
        let t = T0 + i as u64 * 10 * MS;
        mon.on_command(
            &CommandSample {
                t_ns: t,
                channel: "/cmd_vel",
                linear: Some(v),
                angular: Some(v),
                joint_speed_max: Some(v),
                direction_known: true,
            },
            |_| n += 1,
        );
        mon.on_feedback(
            t,
            &FeedbackSample {
                t_ns: t,
                source: FeedbackSource::WheelOdometry,
                linear: Some(v),
                angular: Some(v),
                joint_speed_max: Some(v),
            },
            |_| n += 1,
        );
    }
    // NaN, +inf, -inf on each of three axes.
    assert_eq!(mon.stats().invalid_command_values, 9);
    for a in Axis::ALL {
        if let Some((lo, hi)) = mon.expected_band(a) {
            assert!(lo.is_finite() && hi.is_finite());
        }
    }
}

#[test]
fn hostile_random_event_stream_never_panics() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let vals = [
        0.0,
        1.0,
        -1.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,
        f64::MIN_POSITIVE,
        1e-300,
        7.5,
    ];
    for cfg in [MonitorConfig::ugv("u"), MonitorConfig::manipulator("m"), {
        let mut c = MonitorConfig::ugv("x");
        c.compare_magnitudes = false;
        c.command_timeout_ns = None;
        c.latency_min_ns = 0;
        c.latency_max_ns = 0;
        c.linear.tau_s = 0.0;
        c.linear.max_accel = None;
        c.command_capacity = 2;
        c
    }] {
        let mut mon = ConsistencyMonitor::new(cfg).unwrap();
        let mut count = 0u64;
        let mut t = 0u64;
        for _ in 0..50_000 {
            let r = rng.next_u64();
            t = match r % 7 {
                0 => rng.next_u64(), // anywhere, incl. backwards
                1 => u64::MAX - (r % 3),
                2 => 0,
                _ => t.saturating_add(r % (50 * MS)),
            };
            let pick = |rng: &mut Rng| {
                let k = rng.next_u64() % 12;
                if k >= vals.len() as u64 {
                    None
                } else {
                    Some(vals[k as usize] * if k.is_multiple_of(2) { 1.0 } else { rng.unit() })
                }
            };
            match (r >> 8) % 4 {
                0 => mon.on_command(
                    &CommandSample {
                        t_ns: t,
                        channel: "/cmd_vel",
                        linear: pick(&mut rng),
                        angular: pick(&mut rng),
                        joint_speed_max: pick(&mut rng),
                        direction_known: true,
                    },
                    |_| count += 1,
                ),
                1 => {
                    let s = FeedbackSample {
                        t_ns: rng.next_u64(),
                        source: FeedbackSource::ALL[(rng.next_u64() % 5) as usize],
                        linear: pick(&mut rng),
                        angular: pick(&mut rng),
                        joint_speed_max: pick(&mut rng),
                    };
                    mon.on_feedback(t, &s, |f| {
                        count += 1;
                        let _ = f.detail();
                    });
                }
                2 => mon.set_safety_stop(t, r & 1 == 0),
                _ => mon.tick(t, |_| count += 1),
            }
        }
        assert_eq!(mon.stats().findings, count);
        assert!(mon.stats().clock_regressions > 0);
    }
}

#[test]
fn small_ring_counts_history_underrun_but_keeps_working() {
    let mut cfg = ugv();
    cfg.command_capacity = 2;
    let mut w = World::new(&busy_profile);
    w.cmd_period_ms = 10; // 100 Hz commands, 150 ms window needs ~15 slots
    let (_, mon) = w.run(cfg, 6.0);
    assert!(mon.stats().history_underruns > 0);
    assert_eq!(mon.command_capacity(), 2);
}

#[test]
fn observer_clock_regression_is_clamped() {
    let mut mon = ConsistencyMonitor::new(ugv()).unwrap();
    let s = FeedbackSample {
        t_ns: 5 * MS,
        source: FeedbackSource::Imu,
        linear: None,
        angular: Some(0.0),
        joint_speed_max: None,
    };
    mon.on_feedback(10 * MS, &s, |_| {});
    mon.tick(5 * MS, |_| {});
    mon.set_safety_stop(1, true);
    assert_eq!(mon.stats().clock_regressions, 2);
}

#[test]
fn deterministic_replay() {
    let held = |_: f64, _: Truth| Truth::default();
    let mut w = World::new(&busy_profile);
    w.actuate = &held;
    let (a, _) = w.run(ugv(), 12.0);
    let (b, _) = w.run(ugv(), 12.0);
    assert!(!a.is_empty());
    assert_eq!(a, b);
}

#[test]
fn many_updates_do_not_grow_the_ring() {
    let mut mon = ConsistencyMonitor::new(ugv()).unwrap();
    let cap = mon.command_capacity();
    assert_eq!(cap, 128);
    let mut n = 0u64;
    for k in 0..200_000u64 {
        let t = T0 + k * 5 * MS;
        mon.on_command(
            &CommandSample {
                t_ns: t,
                channel: "/cmd_vel",
                linear: Some((k % 50) as f64 / 50.0),
                angular: Some(0.0),
                joint_speed_max: None,
                direction_known: true,
            },
            |_| n += 1,
        );
        mon.on_feedback(
            t,
            &FeedbackSample {
                t_ns: t,
                source: FeedbackSource::WheelOdometry,
                linear: Some(0.5),
                angular: Some(0.0),
                joint_speed_max: None,
            },
            |_| n += 1,
        );
    }
    assert_eq!(mon.command_capacity(), cap);
}

// ------------------------------------------------------------- manipulator

#[test]
fn manipulator_joint_tracking_and_uncommanded_joint_motion() {
    let mut cfg = MonitorConfig::manipulator("fr3");
    cfg.command_channels = vec!["/joint_cmd".into()];
    let mut mon = ConsistencyMonitor::new(cfg).unwrap();
    let mut f = Vec::new();
    // 1 kHz command and joint state; joint follows with 10 ms lag.
    let mut q = 0.0f64;
    let mut hist = Vec::new();
    for k in 0..6000u64 {
        let t = T0 + k * MS;
        let t_s = k as f64 / 1000.0;
        let cmd = if (1.0..3.0).contains(&t_s) { 0.8 } else { 0.0 };
        hist.push(cmd);
        mon.on_command(
            &CommandSample {
                t_ns: t,
                channel: "/joint_cmd",
                linear: None,
                angular: None,
                joint_speed_max: Some(cmd),
                direction_known: true,
            },
            |x| f.push(x),
        );
        let u = if k >= 10 {
            hist[(k - 10) as usize]
        } else {
            0.0
        };
        q = first_order_step(q, u, 0.001, 0.05, Some(10.0));
        // From 4.5 s the arm moves at 0.5 rad/s with zero command.
        let measured = if t_s >= 4.5 {
            0.5
        } else {
            q + (k % 7) as f64 * 1e-4
        };
        let s = FeedbackSample {
            t_ns: t,
            source: FeedbackSource::JointState,
            linear: None,
            angular: None,
            joint_speed_max: Some(measured),
        };
        mon.on_feedback(t, &s, |x| f.push(x));
    }
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].rule, rules::UNCOMMANDED_MOTION);
    assert_eq!(f[0].severity, Severity::Critical);
    assert!(f[0].t_ns < T0 + 4_700 * MS);
}

// ------------------------------------------------------------------ output

#[test]
fn findings_convert_and_serialise() {
    let held = |_: f64, _: Truth| Truth::default();
    let mut w = World::new(&busy_profile);
    w.actuate = &held;
    let (f, _) = w.run(ugv(), 8.0);
    assert!(!f.is_empty());
    for x in &f {
        let d = x.to_deviation();
        assert!(d.rule.starts_with("robot.motion."));
        assert_eq!(d.severity, x.severity);
        assert!(!d.detail.is_empty());
        let j = serde_json::to_value(x).unwrap();
        assert_eq!(j["rule"], x.rule);
        let ev: Evidence = serde_json::from_value(j["evidence"].clone()).unwrap();
        assert_eq!(ev, x.evidence);
    }
}
