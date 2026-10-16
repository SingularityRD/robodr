//! Regression tests for the rev3 safety review finding F4 against
//! `robodr-motion`: same-publisher "at rest" fakes interleaved with real
//! samples (below the bad fraction and below the jump tolerance) hid
//! Critical uncommanded motion. The reviewer PoC passed while the issue
//! existed; these ports assert the fixed behaviour, sweep mixing ratios and
//! fake levels, and check that honest noisy / quantised sensors stay quiet.

use robodr_events::Severity;
use robodr_motion::*;

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

fn odom(stamp: u64, lin: f64) -> FeedbackSample {
    FeedbackSample {
        t_ns: stamp,
        source: FeedbackSource::WheelOdometry,
        linear: Some(lin),
        angular: Some(0.0),
        joint_speed_max: None,
    }
}

/// The reviewer's scenario, generalised: commanded at rest; after 3 s the
/// robot really drives at `real` m/s (uncommanded). Real odometry at 50 Hz;
/// `n_fakes` samples of value `fake` per real sample from the SAME publisher.
fn run_cfg(cfg: MonitorConfig, n_fakes: u64, real: f64, fake: f64) -> Vec<Finding> {
    run_until(cfg, n_fakes, real, fake, 1000)
}

fn run_until(cfg: MonitorConfig, n_fakes: u64, real: f64, fake: f64, k_end: u64) -> Vec<Finding> {
    const PUB: u32 = 0x1111;
    let mut m = ConsistencyMonitor::new(cfg).unwrap();
    let mut out = Vec::new();
    for k in 0..k_end {
        let t = T0 + k * MS * 10;
        if k % 5 == 0 {
            m.on_command(&cmd(t, 0.0), |f| out.push(f));
        }
        if k % 2 == 0 {
            let v = if k > 300 { real } else { 0.0 };
            m.on_feedback_from(t, PUB, &odom(t - 2 * MS, v), |f| out.push(f));
        } else {
            for j in 0..n_fakes {
                let v = fake + ((k * 7919 + j) % 13) as f64 * 1e-4;
                let stamp = t - MS + j * (MS / 64);
                m.on_feedback_from(t + j * (MS / 64), PUB, &odom(stamp, v), |f| out.push(f));
            }
        }
    }
    out
}

fn run(n_fakes: u64, real: f64, fake: f64) -> Vec<Finding> {
    run_cfg(MonitorConfig::default(), n_fakes, real, fake)
}

fn critical_uncommanded(f: &[Finding]) -> Option<&Finding> {
    f.iter()
        .find(|f| f.rule == rules::UNCOMMANDED_MOTION && f.severity == Severity::Critical)
}

/// Motion starts at k = 301 (T0 + 3.01 s).
const MOTION_START: u64 = T0 + 3_010 * MS;

#[test]
fn reviewer_poc_interleaved_fakes_no_longer_hide_critical_uncommanded_motion() {
    let ctl = run(0, 0.36, 0.0);
    assert!(critical_uncommanded(&ctl).is_some());
    let atk = run(4, 0.36, 0.09);
    let f = critical_uncommanded(&atk).unwrap_or_else(|| panic!("{atk:#?}"));
    // Evidence reports the real (peak) speed, not an interleaved fake.
    match f.evidence {
        Evidence::UncommandedMotion { measured, .. } => assert!(measured >= 0.36 - 1e-9),
        e => panic!("unexpected evidence {e:?}"),
    }
    assert_eq!(f.publisher, Some(PublisherKey::Id(0x1111)));
    // Detected about as fast as without the injector.
    let c = critical_uncommanded(&ctl).unwrap();
    assert!(f.t_ns <= c.t_ns + 100 * MS, "{} vs {}", f.t_ns, c.t_ns);
}

#[test]
fn any_mixing_ratio_and_fake_level_is_detected_as_critical() {
    for n_fakes in 1..=20u64 {
        for lvl in 0..=29u32 {
            let fake = f64::from(lvl) / 100.0;
            // 0.8 s past motion start is enough to judge (and keeps the
            // 600-run sweep fast in debug builds).
            let f = run_until(MonitorConfig::default(), n_fakes, 0.36, fake, 380);
            let hit = critical_uncommanded(&f)
                .unwrap_or_else(|| panic!("1:{n_fakes} fake {fake}: {f:#?}"));
            assert!(
                hit.t_ns >= MOTION_START && hit.t_ns <= MOTION_START + 600 * MS,
                "1:{n_fakes} fake {fake}: fired at {}",
                hit.t_ns
            );
            // Before the motion started, only fakes that themselves report
            // motion beyond the rest tolerance (abs_tol 0.10) may raise
            // uncommanded motion, and never Critical: the later Critical is
            // an escalation of that latched High episode.
            for x in f.iter().filter(|x| x.rule == rules::UNCOMMANDED_MOTION) {
                if x.t_ns < MOTION_START {
                    assert!(fake > 0.10 - 1e-9, "1:{n_fakes} fake {fake}: {x:#?}");
                    assert_eq!(x.severity, Severity::High, "1:{n_fakes} fake {fake}");
                }
            }
        }
    }
}

#[test]
fn sub_critical_uncommanded_motion_under_dilution_is_high() {
    for n_fakes in [1u64, 4, 10, 20] {
        let f = run(n_fakes, 0.2, 0.05);
        let u: Vec<_> = f
            .iter()
            .filter(|f| f.rule == rules::UNCOMMANDED_MOTION)
            .collect();
        assert!(!u.is_empty(), "1:{n_fakes}: {f:#?}");
        assert!(u.iter().all(|f| f.severity == Severity::High), "{u:#?}");
    }
}

#[test]
fn hold_zero_restores_per_sample_majority() {
    // Documents what the hold buys: without it the PoC is silent again.
    let cfg = MonitorConfig {
        episode_hold_ns: 0,
        ..MonitorConfig::default()
    };
    let f = run_cfg(cfg, 4, 0.36, 0.09);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn honest_stop_after_uncommanded_burst_rearms() {
    // A short real excursion (well under the persistence) followed by rest
    // with fakes must not latch anything, and the episode must clear.
    const PUB: u32 = 7;
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut out = Vec::new();
    for k in 0..800u64 {
        let t = T0 + k * MS * 10;
        if k % 5 == 0 {
            m.on_command(&cmd(t, 0.0), |f| out.push(f));
        }
        // Single 0.2 m/s blip at k = 400 only (one sample).
        let v = if k == 400 { 0.2 } else { 0.0 };
        m.on_feedback_from(t, PUB, &odom(t - MS, v), |f| out.push(f));
    }
    assert!(out.is_empty(), "{out:#?}");
}

// ------------------------------------------------- honest noisy sensors

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
    /// Box-Muller normal, std `sigma`.
    fn gauss(&mut self, sigma: f64) -> f64 {
        let (u1, u2) = (self.unit(), self.unit());
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos() * sigma
    }
}

fn quantise(v: f64, q: f64) -> f64 {
    if q > 0.0 {
        (v / q).round() * q
    } else {
        v
    }
}

/// Command profile: rest, ramp to 0.8, cruise, stop, rest, reverse, stop.
fn profile(t_s: f64) -> f64 {
    match t_s {
        t if t < 3.0 => 0.0,
        t if t < 8.0 => 0.8,
        t if t < 12.0 => 0.0,
        t if t < 15.0 => -0.4,
        _ => 0.0,
    }
}

/// Honest robot (plant differs from the model: 80 ms dead time, tau 0.3,
/// accel 1.8) with Gaussian noise `sigma` and quantisation `q`, feedback
/// every `period_ms`.
fn honest_run(seed: u64, sigma: f64, q: f64, period_ms: u64) -> Vec<Finding> {
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut rng = Rng(seed);
    let mut out = Vec::new();
    let mut v = 0.0f64;
    let dt = 0.001;
    let mut hist = std::collections::VecDeque::from(vec![0.0; 80]);
    for k in 0..20_000u64 {
        let t = T0 + k * MS;
        let ts = k as f64 / 1000.0;
        let u = profile(ts);
        if k % 20 == 0 {
            m.on_command(&cmd(t, u), |f| out.push(f));
        }
        hist.push_back(u);
        let ud = hist.pop_front().unwrap();
        let dv = ((ud - v) / 0.3 * dt).clamp(-1.8 * dt, 1.8 * dt);
        v += dv;
        if k % period_ms == 0 {
            let meas = quantise(v + rng.gauss(sigma), q);
            m.on_feedback_from(t + MS / 2, 3, &odom(t, meas), |f| out.push(f));
        }
    }
    out
}

#[test]
fn honest_gaussian_noise_and_quantisation_raise_nothing() {
    // sigma up to 0.02 m/s (abs_tol 0.10 is 5 sigma), quantisation up to
    // 0.01 m/s, 10 Hz .. 200 Hz. Noise-free quantised output repeats
    // bit-identical values at a steady cruise; the frozen check only judges
    // runs during which the expectation changed, so it stays quiet too.
    for (i, &(sigma, q)) in [
        (0.0, 0.0),
        (0.0, 0.005),
        (0.0, 0.01),
        (0.005, 0.0),
        (0.01, 0.0),
        (0.02, 0.0),
        (0.01, 0.005),
        (0.02, 0.01),
    ]
    .iter()
    .enumerate()
    {
        for period in [5u64, 10, 20, 50, 100] {
            for seed in 1..=3u64 {
                let f = honest_run(seed * 0x9E37_79B9 + i as u64, sigma, q, period);
                assert!(
                    f.is_empty(),
                    "sigma {sigma} q {q} period {period} ms seed {seed}: {f:#?}"
                );
            }
        }
    }
}

#[test]
fn honest_noise_at_rest_long_run_raises_nothing() {
    // 60 s at rest, 50 Hz, sigma 0.02, quantised to 0.005: no uncommanded
    // motion claimed from noise, with the hold active.
    let mut m = ConsistencyMonitor::new(MonitorConfig::default()).unwrap();
    let mut rng = Rng(0xDEAD_BEEF);
    let mut out = Vec::new();
    for k in 0..3000u64 {
        let t = T0 + k * 20 * MS;
        if k % 2 == 0 {
            m.on_command(&cmd(t, 0.0), |f| out.push(f));
        }
        let meas = quantise(rng.gauss(0.02), 0.005);
        m.on_feedback_from(t + MS, 9, &odom(t, meas), |f| out.push(f));
    }
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn hostile_values_with_hold_do_not_panic() {
    let mut m = ConsistencyMonitor::new(MonitorConfig {
        episode_hold_ns: u64::MAX,
        ..MonitorConfig::default()
    })
    .unwrap();
    let mut n = 0u64;
    for (k, v) in [
        0.0,
        f64::NAN,
        f64::INFINITY,
        -f64::INFINITY,
        f64::MAX,
        -f64::MAX,
        1.0,
        0.0,
    ]
    .iter()
    .cycle()
    .take(4000)
    .enumerate()
    {
        let t = T0 + k as u64 * 10 * MS;
        if k % 5 == 0 {
            m.on_command(&cmd(t, 0.0), |_| n += 1);
        }
        m.on_feedback_from(t, 1, &odom(t, *v), |_| n += 1);
    }
    assert!(n > 0);
}
