//! Regression tests for the wave-2 safety review findings against
//! `robodr-motion`. Each reviewer PoC passed while the issue existed; these
//! ports assert the fixed behaviour.

use robodr_events::{MotionCommand, Severity};
use robodr_motion::*;

const MS: u64 = 1_000_000;
const T0: u64 = 1_000 * MS;

fn cmd(t: u64, lin: f64, ang: f64) -> CommandSample<'static> {
    CommandSample {
        t_ns: t,
        channel: "/cmd_vel",
        linear: Some(lin),
        angular: Some(ang),
        joint_speed_max: None,
        direction_known: true,
    }
}

fn fbk(stamp: u64, src: FeedbackSource, lin: Option<f64>, ang: Option<f64>) -> FeedbackSample {
    FeedbackSample {
        t_ns: stamp,
        source: src,
        linear: lin,
        angular: ang,
        joint_speed_max: None,
    }
}

fn count(f: &[Finding], rule: &str) -> usize {
    f.iter().filter(|x| x.rule == rule).count()
}

// ------------------------------------------- finding 2: direction reversal

/// Commanded +0.5 m/s / +0.5 rad/s, robot drives and turns the other way;
/// odometry and IMU agree with each other. Feedback mirrors the band
/// (`-(lo+hi)/2`), exactly as in the PoC.
fn reversal_run(mirror: bool, signed_cmd: bool) -> Vec<Finding> {
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    let mc = MotionCommand {
        channel: "/cmd_vel".into(),
        source_guid: None,
        linear_speed: Some(0.5),
        joint_speed: None,
        angular_speed: None,
    };
    for k in 0..1000u64 {
        let t = T0 + k * 10 * MS;
        let (l, a) = if k > 300 { (0.5, 0.5) } else { (0.0, 0.0) };
        if k % 5 == 0 {
            if signed_cmd {
                m.on_command(&cmd(t, l, a), |f| out.push(f));
            } else {
                let mc = MotionCommand {
                    linear_speed: Some(l),
                    ..mc.clone()
                };
                m.on_command(&CommandSample::from_motion_command(&mc, t), |f| out.push(f));
            }
        }
        if k % 2 == 0 {
            let sign = if mirror { -1.0 } else { 1.0 };
            let mid = |ax| {
                m.expected_band(ax)
                    .map(|(lo, hi): (f64, f64)| sign * (lo + hi) / 2.0)
                    .unwrap_or(0.0)
            };
            let (ml, ma) = (mid(Axis::Linear), mid(Axis::Angular));
            let ma = if signed_cmd { Some(ma) } else { None };
            m.on_feedback(
                t,
                &fbk(t - MS, FeedbackSource::WheelOdometry, Some(ml), ma),
                |f| out.push(f),
            );
            m.on_feedback(t, &fbk(t - MS, FeedbackSource::Imu, None, ma), |f| {
                out.push(f)
            });
        }
    }
    out
}

#[test]
fn direction_reversal_is_detected_by_default() {
    let out = reversal_run(true, true);
    let opp: Vec<_> = out
        .iter()
        .filter_map(|f| match f.evidence {
            Evidence::FeedbackDivergence {
                source,
                axis,
                direction: Direction::Opposite,
                ..
            } => Some((source, axis, f.severity)),
            _ => None,
        })
        .collect();
    for want in [
        (FeedbackSource::WheelOdometry, Axis::Linear),
        (FeedbackSource::WheelOdometry, Axis::Angular),
        (FeedbackSource::Imu, Axis::Angular),
    ] {
        let hit = opp.iter().find(|(s, a, _)| (*s, *a) == want);
        let (_, _, sev) = hit.unwrap_or_else(|| panic!("no Opposite for {want:?}: {out:#?}"));
        assert!(*sev >= Severity::High, "{want:?}");
        // Reversing at >= `uncommanded_critical` is Critical: 0.5 m/s
        // exceeds the linear 0.30 at once; the yaw rate is still ramping
        // towards the 0.50 rad/s threshold when its finding fires.
        if want.1 == Axis::Linear {
            assert_eq!(*sev, Severity::Critical, "{want:?}");
        }
    }
    // Odometry and IMU agree: no cross-sensor finding.
    assert_eq!(count(&out, rules::CROSS_SENSOR_DISAGREEMENT), 0, "{out:#?}");
}

#[test]
fn honest_tracking_signed_raises_nothing() {
    let out = reversal_run(false, true);
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn honest_reverse_driving_raises_nothing() {
    // Commanded -0.4 m/s / -0.3 rad/s, robot follows.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..800u64 {
        let t = T0 + k * 10 * MS;
        let (l, a) = if k > 300 { (-0.4, -0.3) } else { (0.0, 0.0) };
        if k % 5 == 0 {
            m.on_command(&cmd(t, l, a), |f| out.push(f));
        }
        if k % 2 == 0 {
            let mid = |ax| {
                m.expected_band(ax)
                    .map(|(lo, hi): (f64, f64)| (lo + hi) / 2.0)
                    .unwrap_or(0.0)
            };
            let (ml, ma) = (mid(Axis::Linear), mid(Axis::Angular));
            m.on_feedback(
                t,
                &fbk(t - MS, FeedbackSource::WheelOdometry, Some(ml), Some(ma)),
                |f| out.push(f),
            );
            m.on_feedback(t, &fbk(t - MS, FeedbackSource::Imu, None, Some(ma)), |f| {
                out.push(f)
            });
            // GNSS speed over ground is a magnitude: compared as one.
            m.on_feedback(
                t,
                &fbk(t - MS, FeedbackSource::Gnss, Some(ml.abs()), None),
                |f| out.push(f),
            );
        }
    }
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn magnitude_only_commands_skip_the_direction_check() {
    // Documented limitation: `MotionCommand` has no sign, so a reversal is
    // invisible on commands built from it (magnitudes match).
    let out = reversal_run(true, false);
    assert!(
        !out.iter().any(|f| matches!(
            f.evidence,
            Evidence::FeedbackDivergence {
                direction: Direction::Opposite,
                ..
            }
        )),
        "{out:#?}"
    );
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn cross_sensor_compares_signed_values() {
    // Odometry claims a left turn, the gyro measures a right turn of the
    // same magnitude: |values| agree, signed values do not.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..300u64 {
        let t = T0 + k * 20 * MS;
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::WheelOdometry, None, Some(0.4)),
            |f| out.push(f),
        );
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::Imu, None, Some(-0.4)),
            |f| out.push(f),
        );
    }
    assert_eq!(count(&out, rules::CROSS_SENSOR_DISAGREEMENT), 1, "{out:#?}");

    // Legacy switch restores magnitude comparison (and the blind spot).
    let cfg = MonitorConfig {
        compare_magnitudes: true,
        ..MonitorConfig::default()
    };
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    for k in 0..300u64 {
        let t = T0 + k * 20 * MS;
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::WheelOdometry, None, Some(0.4)),
            |f| out.push(f),
        );
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::Imu, None, Some(-0.4)),
            |f| out.push(f),
        );
    }
    assert_eq!(count(&out, rules::CROSS_SENSOR_DISAGREEMENT), 0, "{out:#?}");
}

// ------------------------------- findings 1 and 3: interleaving, periodic NaN

#[derive(Clone, Copy)]
enum Fake {
    None,
    /// `n` "at rest" samples per real one, same (unknown) publisher.
    SamePublisher(u64),
    /// One per real sample, from a distinct publisher id.
    DistinctPublisher,
}

/// The robot is commanded to stop; after 3 s something below the observed
/// channel drives it at 1.0 m/s. Real odometry at 50 Hz (every 20 ms).
fn uncommanded_run(fake: Fake, nan_every: Option<u64>) -> (Vec<Finding>, MonitorStats) {
    const REAL: u32 = 0x1111;
    const FAKE: u32 = 0x2222;
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..1000u64 {
        let t = T0 + k * MS * 10;
        if k % 5 == 0 {
            m.on_command(&cmd(t, 0.0, 0.0), |f| out.push(f));
        }
        let real_pub = match fake {
            Fake::DistinctPublisher => REAL,
            _ => PUBLISHER_UNKNOWN,
        };
        if k % 2 == 0 {
            let v = if k > 300 { 1.0 } else { 0.0 };
            let n = k / 2;
            let v = match nan_every {
                Some(e) if n % e == 0 => f64::NAN,
                _ => v,
            };
            m.on_feedback_from(
                t,
                real_pub,
                &fbk(
                    t - 2 * MS,
                    FeedbackSource::WheelOdometry,
                    Some(v),
                    Some(0.0),
                ),
                |f| out.push(f),
            );
        }
        let n_fakes = match fake {
            Fake::None => 0,
            Fake::SamePublisher(n) => n,
            Fake::DistinctPublisher => 1,
        };
        if k % 2 == 1 {
            let fake_pub = match fake {
                Fake::DistinctPublisher => FAKE,
                _ => PUBLISHER_UNKNOWN,
            };
            for j in 0..n_fakes {
                // Plausible "at rest" values with noise; stamps between the
                // real ones (strictly increasing).
                let noise = ((k * 7919 + j) % 13) as f64 * 1e-3;
                let stamp = t - MS + j * (MS / 4);
                let now = t + j * (MS / 4);
                m.on_feedback_from(
                    now,
                    fake_pub,
                    &fbk(stamp, FeedbackSource::WheelOdometry, Some(noise), Some(0.0)),
                    |f| out.push(f),
                );
            }
        }
    }
    (out, m.stats())
}

fn uncommanded_critical(f: &[Finding]) -> bool {
    f.iter()
        .any(|x| x.rule == rules::UNCOMMANDED_MOTION && x.severity == Severity::Critical)
}

#[test]
fn control_uncommanded_motion_is_critical() {
    let (f, _) = uncommanded_run(Fake::None, None);
    assert!(uncommanded_critical(&f), "{f:#?}");
}

#[test]
fn interleaved_fake_feedback_same_publisher_still_detected() {
    // The PoC exactly: one fake per real sample, publisher unknown. The
    // episode-based persistence is diluted to 50 % bad, not reset.
    let (f, _) = uncommanded_run(Fake::SamePublisher(1), None);
    assert!(uncommanded_critical(&f), "{f:#?}");
    // Up to three fakes per real sample (25 % bad) still fires.
    let (f, _) = uncommanded_run(Fake::SamePublisher(3), None);
    assert!(uncommanded_critical(&f), "{f:#?}");
}

#[test]
fn interleaved_fake_feedback_distinct_publisher_is_isolated_and_flagged() {
    let (f, stats) = uncommanded_run(Fake::DistinctPublisher, None);
    let u = f
        .iter()
        .find(|x| x.rule == rules::UNCOMMANDED_MOTION)
        .unwrap_or_else(|| panic!("{f:#?}"));
    assert_eq!(u.severity, Severity::Critical);
    assert_eq!(
        u.publisher,
        Some(PublisherKey::Id(0x1111)),
        "attributed to the real publisher"
    );
    let mp: Vec<_> = f
        .iter()
        .filter(|x| x.rule == rules::MULTIPLE_FEEDBACK_PUBLISHERS)
        .collect();
    assert_eq!(mp.len(), 1, "latched once: {f:#?}");
    assert_eq!(mp[0].severity, Severity::High);
    match mp[0].evidence {
        Evidence::MultiplePublishers { source, active, .. } => {
            assert_eq!(source, FeedbackSource::WheelOdometry);
            assert_eq!(active, 2);
        }
        e => panic!("{e:?}"),
    }
    assert!(mp[0].to_deviation().detail.contains("publisher"));
    assert_eq!(stats.publisher_overflow, 0);
}

#[test]
fn driver_restart_with_new_publisher_is_not_multiple_publishers() {
    // Publisher A until 3 s, then (after a short gap) publisher B: a clean
    // hand-over, not interleaving.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..400u64 {
        let t = T0 + k * 20 * MS;
        if k % 2 == 0 {
            m.on_command(&cmd(t, 0.0, 0.0), |f| out.push(f));
        }
        if (150..160).contains(&k) {
            continue; // restart gap
        }
        let p = if k < 150 { 0xA } else { 0xB };
        m.on_feedback_from(
            t,
            p,
            &fbk(t - MS, FeedbackSource::WheelOdometry, Some(0.0), Some(0.0)),
            |f| out.push(f),
        );
    }
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn publisher_flood_is_bounded_and_does_not_panic() {
    // 1000 distinct publisher ids on one source: fixed table, overflow
    // counted, still flagged once, nothing panics.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..1000u64 {
        let t = T0 + k * 5 * MS;
        m.on_feedback_from(
            t,
            publisher_id(&k.to_le_bytes()),
            &fbk(t - MS, FeedbackSource::Imu, None, Some(0.0)),
            |f| out.push(f),
        );
    }
    assert!(m.stats().publisher_overflow > 900);
    // Flagged once as interleaving and once as overflow.
    assert_eq!(
        count(&out, rules::MULTIPLE_FEEDBACK_PUBLISHERS),
        2,
        "{out:#?}"
    );
    assert_eq!(
        out.iter()
            .filter(|x| matches!(x.evidence, Evidence::PublisherOverflow { .. }))
            .count(),
        1,
        "{out:#?}"
    );
}

#[test]
fn periodic_nan_does_not_suppress_detection() {
    // NaN every 8th real sample: the Critical still fires, and the NaN rate
    // while the robot moves is escalated to High.
    let (f, stats) = uncommanded_run(Fake::None, Some(8));
    assert!(uncommanded_critical(&f), "{f:#?}");
    assert!(
        f.iter().any(|x| x.rule == rules::INVALID_FEEDBACK
            && x.severity == Severity::High
            && matches!(x.evidence, Evidence::NonFiniteRate { .. })),
        "{f:#?}"
    );
    assert!(stats.invalid_feedback_values > 50);
}

#[test]
fn nan_at_rest_stays_medium() {
    // Same NaN pattern on a robot that really is at rest: a driver fault,
    // not blinding; only the single Medium.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..500u64 {
        let t = T0 + k * 20 * MS;
        if k % 2 == 0 {
            m.on_command(&cmd(t, 0.0, 0.0), |f| out.push(f));
        }
        let v = if k % 8 == 0 { f64::NAN } else { 0.0 };
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::WheelOdometry, Some(v), Some(0.0)),
            |f| out.push(f),
        );
    }
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].severity, Severity::Medium);
}

#[test]
fn periodic_nan_does_not_break_frozen_detection() {
    // Frozen odometry while commanded to move, with a NaN every 8th sample.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..500u64 {
        let t = T0 + k * 20 * MS;
        let l = if k > 100 { 1.0 } else { 0.0 };
        if k % 2 == 0 {
            m.on_command(&cmd(t, l, 0.0), |f| out.push(f));
        }
        let v = if k % 8 == 0 {
            f64::NAN
        } else if k > 100 {
            0.987
        } else {
            0.0
        };
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::WheelOdometry, Some(v), Some(0.0)),
            |f| out.push(f),
        );
    }
    assert!(
        out.iter()
            .any(|x| matches!(x.evidence, Evidence::FrozenValues { .. })),
        "{out:#?}"
    );
}

// ------------- finding 1 (cont.): unattributed injector outnumbering the real

fn stream_rule(f: &[Finding]) -> Vec<&Finding> {
    f.iter()
        .filter(|x| x.rule == rules::INCONSISTENT_FEEDBACK_STREAM)
        .collect()
}

#[test]
fn many_fakes_per_real_sample_are_flagged_as_inconsistent_stream() {
    // Ten "at rest" samples per real one under the same (unknown) identity
    // dilute the uncommanded episode below `min_bad_fraction`, but every
    // real <-> fake transition is a jump the platform cannot produce.
    let (f, _) = uncommanded_run(Fake::SamePublisher(10), None);
    let s = stream_rule(&f);
    assert_eq!(s.len(), 1, "latched once per episode: {f:#?}");
    assert_eq!(s[0].severity, Severity::High);
    match s[0].evidence {
        Evidence::InconsistentStream {
            source,
            axis,
            jumps,
            implied_rate,
            ..
        } => {
            assert_eq!(
                (source, axis),
                (FeedbackSource::WheelOdometry, Axis::Linear)
            );
            assert!(jumps >= 10);
            assert!(implied_rate > 20.0, "{implied_rate}");
        }
        e => panic!("{e:?}"),
    }
    assert!(s[0].to_deviation().detail.contains("interleaved"));
    // The one-for-one PoC pattern is flagged this way too (in addition to
    // the uncommanded-motion Critical).
    let (f, _) = uncommanded_run(Fake::SamePublisher(1), None);
    assert_eq!(stream_rule(&f).len(), 1, "{f:#?}");
}

#[test]
fn single_step_change_is_not_an_inconsistent_stream() {
    // The control run steps 0 -> 1.0 m/s in one sample (one implausible
    // jump): a bump, not a stream of them. Distinct publishers are each
    // self-consistent.
    let (f, _) = uncommanded_run(Fake::None, None);
    assert!(stream_rule(&f).is_empty(), "{f:#?}");
    let (f, _) = uncommanded_run(Fake::DistinctPublisher, None);
    assert!(stream_rule(&f).is_empty(), "{f:#?}");
}

#[test]
fn honest_noisy_high_rate_gyro_is_not_an_inconsistent_stream() {
    // 200 Hz gyro, +/-0.06 rad/s noise, turning at 0.4 rad/s.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for k in 0..2000u64 {
        let t = T0 + k * 5 * MS;
        if k % 10 == 0 {
            m.on_command(&cmd(t, 0.0, 0.4), |f| out.push(f));
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let noise = ((x % 1201) as f64 / 1200.0 - 0.5) * 0.12;
        let w = m
            .expected_band(Axis::Angular)
            .map(|(lo, hi)| (lo + hi) / 2.0)
            .unwrap_or(0.0);
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::Imu, None, Some(w + noise)),
            |f| out.push(f),
        );
    }
    assert!(stream_rule(&out).is_empty(), "{out:#?}");
}

#[test]
fn inconsistent_stream_check_can_be_disabled() {
    let cfg = MonitorConfig {
        jump_min_count: 0,
        ..MonitorConfig::default()
    };
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    for k in 0..500u64 {
        let t = T0 + k * 10 * MS;
        let v = if k % 2 == 0 { 1.0 } else { 0.0 };
        m.on_feedback(t, &fbk(t - MS, FeedbackSource::Gnss, Some(v), None), |f| {
            out.push(f)
        });
    }
    assert!(stream_rule(&out).is_empty(), "{out:#?}");
}

// ------------------- finding 3 (cont.): an all-invalid stream is never "OK"

#[test]
fn all_nan_stream_at_rest_escalates_to_high() {
    // Odometry that only ever sends NaN: the monitor cannot see uncommanded
    // motion at all, so the state is "unknown", reported High even though
    // the command is rest and nothing is expected to move.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..300u64 {
        let t = T0 + k * 20 * MS;
        if k % 2 == 0 {
            m.on_command(&cmd(t, 0.0, 0.0), |f| out.push(f));
        }
        m.on_feedback(
            t,
            &fbk(t - MS, FeedbackSource::WheelOdometry, Some(f64::NAN), None),
            |f| out.push(f),
        );
    }
    let high: Vec<_> = out
        .iter()
        .filter(|x| x.rule == rules::INVALID_FEEDBACK && x.severity == Severity::High)
        .collect();
    assert_eq!(high.len(), 1, "latched: {out:#?}");
    match high[0].evidence {
        Evidence::NonFiniteRate {
            invalid, window, ..
        } => assert_eq!(invalid, window),
        e => panic!("{e:?}"),
    }
}

#[test]
fn reviewer_poc_nan_every_8th_no_longer_hides_motion() {
    // The PoC asserted <= 2 findings and no uncommanded motion.
    let (f, _) = uncommanded_run(Fake::None, Some(8));
    assert!(count(&f, rules::UNCOMMANDED_MOTION) >= 1, "{f:#?}");
    assert!(f.len() > 2, "{f:#?}");
}
