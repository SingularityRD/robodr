//! Regression tests for the remaining `robodr-motion` gaps after rev3:
//!
//! 1. the cross-sensor rule judged the per-sample majority, so agreeing
//!    fakes interleaved on one stream diluted a real disagreement;
//! 2. a divergence episode latched at High/Medium never escalated when the
//!    robot then moved against its command at speed;
//! 3. `publisher_id` is a 32-bit hash an adversary can collide by choosing
//!    its GUID, and overflow publishers shared a tracked publisher's slot;
//! 4. (frozen at cruise: see `scenarios.rs` / `rev3_safety_regressions.rs`).
//!
//! Each attack is swept over mixing ratios and fake levels, with a control
//! showing the old behaviour where a switch restores it, and honest noisy
//! sensors must stay quiet.

use robodr_events::Severity;
use robodr_motion::*;
use std::collections::HashMap;

const MS: u64 = 1_000_000;
const T0: u64 = 1_000 * MS;

fn cmd(t: u64, lin: f64) -> CommandSample<'static> {
    CommandSample {
        t_ns: t,
        channel: "/cmd_vel",
        linear: Some(lin),
        angular: Some(0.0),
        joint_speed_max: None,
        direction_known: true,
    }
}

fn sample(stamp: u64, source: FeedbackSource, lin: f64) -> FeedbackSample {
    FeedbackSample {
        t_ns: stamp,
        source,
        linear: Some(lin),
        angular: None,
        joint_speed_max: None,
    }
}

fn by_rule<'a>(f: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.rule == rule).collect()
}

// ------------------------------------------------ gap 1: cross-sensor dilution

/// Visual odometry (`Other`, 50 Hz) and GNSS (10 Hz) both report 1.0 m/s;
/// from 3 s the real GNSS reports 0.0 (they now disagree by 1.0, tolerance
/// 0.2 + 25 %). `n_fakes` samples of `fake` per real GNSS sample are
/// interleaved on the GNSS stream from the SAME publisher, chosen to agree
/// with the visual odometry. Neither source is command-checked.
fn cross_run(cfg: MonitorConfig, n_fakes: u64, fake: f64, secs: u64) -> Vec<Finding> {
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    for k in 0..secs * 100 {
        let t = T0 + k * 10 * MS;
        if k % 2 == 0 {
            let v = 1.0 + ((k * 31) % 7) as f64 * 1e-3;
            m.on_feedback_from(t, 1, &sample(t - MS, FeedbackSource::Other, v), |f| {
                out.push(f)
            });
        }
        if k % 10 == 0 {
            let real = if k >= 300 { 0.0 } else { 1.0 };
            m.on_feedback_from(t, 2, &sample(t - MS, FeedbackSource::Gnss, real), |f| {
                out.push(f)
            });
            if k >= 300 {
                for j in 0..n_fakes {
                    let dt = (j + 1) * (9 * MS / (n_fakes + 1));
                    let v = fake + ((k + j) % 5) as f64 * 1e-3;
                    m.on_feedback_from(
                        t + dt,
                        2,
                        &sample(t + dt - MS, FeedbackSource::Gnss, v),
                        |f| out.push(f),
                    );
                }
            }
        }
    }
    out
}

const DISAGREE_START: u64 = T0 + 3_000 * MS;

#[test]
fn cross_sensor_disagreement_survives_any_mixing_ratio_and_fake_level() {
    for n_fakes in 0..=20u64 {
        for lvl in 0..=16u32 {
            // 0.6 .. 1.4: every level agrees with the 1.0 m/s odometry.
            let fake = 0.6 + f64::from(lvl) * 0.05;
            let f = cross_run(MonitorConfig::default(), n_fakes, fake, 6);
            let c = by_rule(&f, rules::CROSS_SENSOR_DISAGREEMENT);
            let hit = c
                .first()
                .unwrap_or_else(|| panic!("1:{n_fakes} fake {fake}: {f:#?}"));
            assert_eq!(hit.severity, Severity::High);
            assert!(
                hit.t_ns >= DISAGREE_START + 900 * MS && hit.t_ns <= DISAGREE_START + 1_500 * MS,
                "1:{n_fakes} fake {fake}: fired at {}",
                hit.t_ns
            );
            match hit.evidence {
                Evidence::CrossSensorDisagreement {
                    axis,
                    source_a,
                    source_b,
                    more_trusted,
                    ..
                } => {
                    assert_eq!(axis, Axis::Linear);
                    assert_eq!(
                        (source_a, source_b),
                        (FeedbackSource::Gnss, FeedbackSource::Other)
                    );
                    assert_eq!(more_trusted, Some(FeedbackSource::Gnss));
                }
                e => panic!("{e:?}"),
            }
            // One finding per episode.
            assert_eq!(c.len(), 1, "1:{n_fakes} fake {fake}: {c:#?}");
        }
    }
}

#[test]
fn cross_sensor_hold_zero_is_diluted_again() {
    // Control: without the hold the per-sample majority is diluted below
    // the 25 % bad fraction by a single fake per real GNSS sample.
    let cfg = MonitorConfig {
        episode_hold_ns: 0,
        ..MonitorConfig::default()
    };
    let f = cross_run(cfg.clone(), 1, 1.0, 6);
    assert!(
        by_rule(&f, rules::CROSS_SENSOR_DISAGREEMENT).is_empty(),
        "{f:#?}"
    );
    // ...and without fakes it still fires.
    let f = cross_run(cfg, 0, 1.0, 6);
    assert_eq!(by_rule(&f, rules::CROSS_SENSOR_DISAGREEMENT).len(), 1);
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
        ((self.next_u64() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }
    fn gauss(&mut self, sigma: f64) -> f64 {
        let (u1, u2) = (self.unit(), self.unit());
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos() * sigma
    }
}

#[test]
fn honest_noisy_cross_checked_sensors_with_outliers_raise_nothing() {
    // Odometry (50 Hz, sigma 0.02) and GNSS (5..20 Hz, sigma 0.06) follow
    // the same speed profile; GNSS also has a gross multipath outlier
    // (+0.8 m/s) in about 1 of 30 fixes. The hold must not turn these
    // sparse disagreements into a finding.
    for (seed, gnss_period) in [(1u64, 5u64), (2, 10), (3, 20), (4, 10)] {
        let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
        let mut rng = Rng(0xC0FF_EE00 + seed);
        let mut out = Vec::new();
        for k in 0..6_000u64 {
            let t = T0 + k * 10 * MS;
            let ts = k as f64 / 100.0;
            let truth = (ts / 6.0).sin().abs() * 1.5;
            if k % 2 == 0 {
                let v = truth + rng.gauss(0.02);
                m.on_feedback_from(t, 1, &sample(t - MS, FeedbackSource::Other, v), |f| {
                    out.push(f)
                });
            }
            if k % gnss_period == 0 {
                let mut v = (truth + rng.gauss(0.06)).abs();
                if rng.next_u64().is_multiple_of(30) {
                    v += 0.8;
                }
                m.on_feedback_from(t, 2, &sample(t - MS, FeedbackSource::Gnss, v), |f| {
                    out.push(f)
                });
            }
        }
        assert!(
            by_rule(&out, rules::CROSS_SENSOR_DISAGREEMENT).is_empty(),
            "seed {seed} gnss {gnss_period}: {out:#?}"
        );
    }
}

// ------------------------------------------- gap 2: opposite-direction escalation

/// Commanded +0.5 m/s from 1 s. Odometry (50 Hz, real) first reports mild
/// under-motion (`under` m/s) from 4 s (episode latches at Medium), then
/// from 6 s the robot really moves against the command at `reverse` m/s.
/// `n_fakes` samples at the commanded speed are interleaved per real one
/// (same publisher).
fn reverse_run(cfg: MonitorConfig, n_fakes: u64, under: f64, reverse: f64) -> Vec<Finding> {
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    for k in 0..900u64 {
        let t = T0 + k * 10 * MS;
        let c = if k >= 100 { 0.5 } else { 0.0 };
        if k % 5 == 0 {
            m.on_command(&cmd(t, c), |f| out.push(f));
        }
        if k % 2 == 0 {
            let v = if k >= 500 {
                reverse
            } else if k >= 300 {
                under
            } else {
                m.expected_band(Axis::Linear)
                    .map(|(lo, hi)| (lo + hi) / 2.0)
                    .unwrap_or(0.0)
            };
            let s = FeedbackSample {
                angular: Some(0.0),
                ..sample(t - MS, FeedbackSource::WheelOdometry, v)
            };
            m.on_feedback_from(t, 9, &s, |f| out.push(f));
        } else if k >= 300 {
            for j in 0..n_fakes {
                let dt = j * (9 * MS / (n_fakes + 1));
                let s = FeedbackSample {
                    angular: Some(0.0),
                    ..sample(
                        t + dt - MS,
                        FeedbackSource::WheelOdometry,
                        0.5 + ((k + j) % 3) as f64 * 1e-3,
                    )
                };
                m.on_feedback_from(t + dt, 9, &s, |f| out.push(f));
            }
        }
    }
    out
}

fn divergences(f: &[Finding]) -> Vec<(Severity, Direction, f64, u64)> {
    f.iter()
        .filter_map(|x| match x.evidence {
            Evidence::FeedbackDivergence {
                axis: Axis::Linear,
                direction,
                measured,
                ..
            } => Some((x.severity, direction, measured, x.t_ns)),
            _ => None,
        })
        .collect()
}

const REVERSE_START: u64 = T0 + 5_000 * MS;

#[test]
fn latched_under_motion_escalates_to_critical_when_robot_reverses() {
    for n_fakes in [0u64, 1, 2, 4, 8, 16] {
        for reverse in [-0.3, -0.45, -0.6, -1.0] {
            let f = reverse_run(MonitorConfig::default(), n_fakes, 0.2, reverse);
            let d = divergences(&f);
            // First the Medium under-motion (safety stop not wired)...
            assert_eq!(
                d.first().map(|x| (x.0, x.1)),
                Some((Severity::Medium, Direction::Under)),
                "1:{n_fakes} rev {reverse}: {d:#?}"
            );
            // ...then exactly one Critical escalation, Opposite, reporting
            // the real reverse speed, soon after the reversal.
            let crit: Vec<_> = d.iter().filter(|x| x.0 == Severity::Critical).collect();
            assert_eq!(crit.len(), 1, "1:{n_fakes} rev {reverse}: {d:#?}");
            let (_, dir, measured, t) = *crit[0];
            assert_eq!(dir, Direction::Opposite);
            assert!((measured - reverse).abs() < 0.01, "{measured} vs {reverse}");
            assert!(
                t > REVERSE_START && t <= REVERSE_START + 400 * MS,
                "1:{n_fakes} rev {reverse}: at {t}"
            );
            assert_eq!(d.len(), 2, "1:{n_fakes} rev {reverse}: {d:#?}");
        }
    }
}

#[test]
fn slow_reversal_under_dilution_stays_high_or_below() {
    // Reversing slower than uncommanded_critical (0.30 m/s): no Critical.
    for n_fakes in [0u64, 4, 16] {
        let f = reverse_run(MonitorConfig::default(), n_fakes, 0.2, -0.2);
        let d = divergences(&f);
        assert!(!d.is_empty(), "{f:#?}");
        assert!(d.iter().all(|x| x.0 < Severity::Critical), "{d:#?}");
    }
}

#[test]
fn reversal_without_preceding_episode_is_critical_once() {
    // Straight from tracking to reversing at speed.
    for n_fakes in [0u64, 4, 16] {
        let f = reverse_run(MonitorConfig::default(), n_fakes, f64::NAN, -0.6);
        let d = divergences(&f);
        let crit = d.iter().filter(|x| x.0 == Severity::Critical).count();
        assert_eq!(crit, 1, "1:{n_fakes}: {d:#?}");
    }
}

#[test]
fn honest_tracking_with_fakes_absent_raises_no_divergence() {
    let f = reverse_run(MonitorConfig::default(), 0, 0.5, 0.5);
    assert!(divergences(&f).is_empty(), "{f:#?}");
}

// --------------------------------------------- gap 3: GUID keys, overflow slot

/// Two different 16-byte GUIDs whose legacy 32-bit `publisher_id`
/// collides: a birthday search (~2^16 tries) over the last 8 bytes, as an
/// adversary choosing its GUID would do. (Varying only 4 bytes would not
/// do: FNV-1a over 4 free bytes is injective.)
fn colliding_guids() -> ([u8; 16], [u8; 16]) {
    let mut seen: HashMap<u32, [u8; 16]> = HashMap::new();
    let mut g = [0x01u8, 0x0f, 0xaa, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    for i in 0u64.. {
        // splitmix64: 8 well-mixed bytes per try.
        let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        g[8..].copy_from_slice(&z.to_le_bytes());
        let h = publisher_id(&g);
        if let Some(prev) = seen.insert(h, g) {
            return (prev, g);
        }
    }
    unreachable!()
}

/// Commanded rest; from 3 s the robot really moves at 0.36 m/s
/// (uncommanded, Critical). An injector with GUID `attacker` interleaves
/// `n_fakes` "at rest" samples per real one on the same topic.
fn guid_run(
    cfg: MonitorConfig,
    real: [u8; 16],
    attacker: [u8; 16],
    n_fakes: u64,
    use_guid: bool,
) -> Vec<Finding> {
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    let mut feed = |m: &mut ConsistencyMonitor, t: u64, g: &[u8; 16], v: f64| {
        let s = FeedbackSample {
            angular: Some(0.0),
            ..sample(t - MS, FeedbackSource::WheelOdometry, v)
        };
        if use_guid {
            m.on_feedback_guid(t, g, &s, |f| out.push(f));
        } else {
            m.on_feedback_from(t, publisher_id(g), &s, |f| out.push(f));
        }
    };
    for k in 0..700u64 {
        let t = T0 + k * 10 * MS;
        if k % 5 == 0 {
            m.on_command(&cmd(t, 0.0), |_| {});
        }
        if k % 2 == 0 {
            feed(&mut m, t, &real, if k > 300 { 0.36 } else { 0.0 });
        } else {
            for j in 0..n_fakes {
                let dt = j * (9 * MS / (n_fakes + 1));
                feed(&mut m, t + dt, &attacker, 0.0);
            }
        }
    }
    out
}

#[test]
fn colliding_legacy_ids_merge_but_full_guids_stay_separate() {
    let (real, atk) = colliding_guids();
    assert_ne!(real, atk);
    assert_eq!(publisher_id(&real), publisher_id(&atk));
    let cfg = MonitorConfig {
        // Without the hold, only per-publisher separation protects.
        episode_hold_ns: 0,
        jump_min_count: 0,
        ..MonitorConfig::default()
    };
    // Legacy hash: the attacker shares the real writer's slot, is not seen
    // as a second publisher, and dilutes the episode below the fraction.
    let f = guid_run(cfg.clone(), real, atk, 4, false);
    assert!(by_rule(&f, rules::MULTIPLE_FEEDBACK_PUBLISHERS).is_empty());
    assert!(by_rule(&f, rules::UNCOMMANDED_MOTION).is_empty(), "{f:#?}");
    // Full GUID: separate slots, interleaving flagged, Critical attributed
    // to the real writer.
    for n_fakes in [1u64, 4, 16] {
        let f = guid_run(cfg.clone(), real, atk, n_fakes, true);
        let mp = by_rule(&f, rules::MULTIPLE_FEEDBACK_PUBLISHERS);
        assert_eq!(mp.len(), 1, "{f:#?}");
        let u = by_rule(&f, rules::UNCOMMANDED_MOTION);
        assert_eq!(u.len(), 1, "{f:#?}");
        assert_eq!(u[0].severity, Severity::Critical);
        assert_eq!(u[0].publisher, Some(PublisherKey::Guid(real)));
        let d = u[0].to_deviation().detail;
        assert!(d.contains(&PublisherKey::Guid(real).to_string()), "{d}");
    }
}

#[test]
fn guid_and_id_namespaces_do_not_collide() {
    // A caller id whose bytes equal part of a GUID is a different
    // publisher: interleaving them is flagged, not merged.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..50u64 {
        let t = T0 + k * 10 * MS;
        let s = sample(t - MS, FeedbackSource::Imu, 0.0);
        if k % 2 == 0 {
            m.on_feedback_guid(t, &[0; 16], &s, |f| out.push(f));
        } else {
            m.on_feedback_key(t, PublisherKey::Id(0), &s, |f| out.push(f));
        }
    }
    assert_eq!(by_rule(&out, rules::MULTIPLE_FEEDBACK_PUBLISHERS).len(), 1);
    assert_eq!(m.stats().publisher_overflow, 0);
}

#[test]
fn flood_beyond_slots_never_shares_the_real_writers_slot() {
    // Three other writers take slots 0..2 first, so the real writer gets
    // the LAST tracked slot (which overflow used to share). Then 12
    // flooding GUIDs send "at rest" samples, 4 per real sample. With the
    // hold off, sharing the slot would dilute the Critical away.
    let cfg = MonitorConfig {
        episode_hold_ns: 0,
        jump_min_count: 0,
        ..MonitorConfig::default()
    };
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    let real = [0x42u8; 16];
    let g = |i: u8| {
        let mut x = [0x13u8; 16];
        x[15] = i;
        x
    };
    for i in 0..3 {
        m.on_feedback_guid(
            T0,
            &g(i),
            &sample(T0 - MS, FeedbackSource::WheelOdometry, 0.0),
            |f| out.push(f),
        );
    }
    for k in 1..700u64 {
        let t = T0 + k * 10 * MS;
        if k % 5 == 0 {
            m.on_command(&cmd(t, 0.0), |_| {});
        }
        if k % 2 == 0 {
            let v = if k > 300 { 0.36 } else { 0.0 };
            let s = sample(t - MS, FeedbackSource::WheelOdometry, v);
            m.on_feedback_guid(t, &real, &s, |f| out.push(f));
        } else {
            for j in 0..4u64 {
                let dt = j * 2 * MS;
                let s = sample(t + dt - MS, FeedbackSource::WheelOdometry, 0.0);
                m.on_feedback_guid(t + dt, &g(10 + ((k * 4 + j) % 12) as u8), &s, |f| {
                    out.push(f)
                });
            }
        }
    }
    assert!(m.stats().publisher_overflow > 0);
    let u = by_rule(&out, rules::UNCOMMANDED_MOTION);
    assert_eq!(u.len(), 1, "{out:#?}");
    assert_eq!(u[0].severity, Severity::Critical);
    assert_eq!(u[0].publisher, Some(PublisherKey::Guid(real)));
    let ov: Vec<_> = out
        .iter()
        .filter(|x| matches!(x.evidence, Evidence::PublisherOverflow { .. }))
        .collect();
    assert_eq!(ov.len(), 1, "overflow flagged once: {ov:#?}");
    assert_eq!(ov[0].severity, Severity::High);
    assert!(ov[0].to_deviation().detail.contains("more than 4"));
}

#[test]
fn overflow_flag_rearms_after_the_overflow_slot_goes_quiet() {
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    let mut t = T0;
    for round in 0..2u8 {
        for k in 0..20u8 {
            t += 10 * MS;
            let mut g = [round; 16];
            g[15] = k % 6; // 6 writers > 4 slots
            m.on_feedback_guid(t, &g, &sample(t - MS, FeedbackSource::Imu, 0.0), |f| {
                out.push(f)
            });
        }
        // Silence beyond publisher_expiry_ns (2 s).
        t += 3_000 * MS;
    }
    let ov = out
        .iter()
        .filter(|x| matches!(x.evidence, Evidence::PublisherOverflow { .. }))
        .count();
    assert_eq!(ov, 2, "{out:#?}");
}
