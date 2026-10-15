//! Property-style randomized tests (std-only xorshift PRNG, fixed seeds so
//! failures reproduce). A reference model in this file tracks what the
//! firewall emitted per channel and checks invariants on every verdict.

mod common;
use common::*;
use robodr_firewall::*;

const SEEDS: u64 = 24;
const STEPS: usize = 20_000;

#[derive(Clone, Copy)]
struct Cfg {
    platform: PlatformConfig,
    lin_acc: Option<f64>,
    ang_acc: Option<f64>,
    joint_acc: Option<f64>,
    lin_jerk: Option<f64>,
    rate: Option<RateLimit>,
    limit_decel: bool,
}

fn random_cfg(r: &mut Rng) -> Cfg {
    let fail_behaviour = match r.below(2) {
        0 => FailBehaviour::ZeroVelocity,
        _ => FailBehaviour::HoldLast {
            max_hold_ns: r.below(300) * MS,
        },
    };
    let opt = |r: &mut Rng, lo: f64, hi: f64| {
        if r.chance(0.6) {
            Some(r.range(lo, hi))
        } else {
            None
        }
    };
    Cfg {
        platform: PlatformConfig {
            fail_behaviour,
            foreign_source_action: if r.chance(0.5) {
                ForeignSourceAction::Drop
            } else {
                ForeignSourceAction::Substitute
            },
            event_capacity: 64,
            ..Default::default()
        },
        lin_acc: opt(r, 0.1, 5.0),
        ang_acc: opt(r, 0.1, 10.0),
        joint_acc: opt(r, 0.1, 10.0),
        lin_jerk: opt(r, 1.0, 50.0),
        rate: if r.chance(0.3) {
            Some(RateLimit {
                per_second: 1 + r.below(200) as u32,
                burst: 1 + r.below(5) as u32,
            })
        } else {
            None
        },
        limit_decel: r.chance(0.3),
    }
}

fn build_cfg(c: Cfg, locked: bool) -> Fx {
    build(c.platform, locked, |b, a| {
        b.max_linear_accel = c.lin_acc;
        b.max_angular_accel = c.ang_acc;
        b.max_linear_jerk = c.lin_jerk;
        b.rate_limit = c.rate;
        b.limit_deceleration = c.limit_decel;
        a.max_joint_accel = c.joint_acc;
        a.rate_limit = c.rate;
        a.limit_deceleration = c.limit_decel;
    })
}

fn value(r: &mut Rng, limit: f64) -> f64 {
    match r.below(100) {
        0 => f64::NAN,
        1 => f64::INFINITY,
        2 => f64::NEG_INFINITY,
        3 => f64::MAX * if r.chance(0.5) { 1.0 } else { -1.0 },
        4 => f64::MIN_POSITIVE,
        5 => -0.0,
        6..=25 => 0.0,
        _ => r.range(-2.5 * limit, 2.5 * limit),
    }
}

fn raw(m: &Motion) -> Vec<f64> {
    match m {
        Motion::Twist(t) => vec![
            t.linear.x,
            t.linear.y,
            t.linear.z,
            t.angular.x,
            t.angular.y,
            t.angular.z,
        ],
        Motion::Joints(j) => j.as_slice().to_vec(),
    }
}

/// Speed check with an independent (naive) norm.
fn within_speed(m: &Motion) -> bool {
    let tol = 1.0 + 1e-12;
    match m {
        Motion::Twist(t) => norm3(t.linear) <= LIN * tol && norm3(t.angular) <= ANG * tol,
        Motion::Joints(j) => j.as_slice().iter().all(|x| x.abs() <= JOINT * tol),
    }
}

fn decelerates(prev: &[f64], out: &[f64]) -> bool {
    prev.iter()
        .zip(out)
        .all(|(p, o)| *o == 0.0 || (p * o > 0.0 && o.abs() <= p.abs()))
}

/// (group-0 step, group-1 step) like the firewall's groups.
fn step_mags(prev: &[f64], out: &[f64], twist: bool) -> (f64, f64) {
    let d: Vec<f64> = out.iter().zip(prev).map(|(o, p)| o - p).collect();
    if twist {
        let n = |s: &[f64]| s.iter().map(|x| x * x).sum::<f64>().sqrt();
        (n(&d[0..3]), n(&d[3..6]))
    } else {
        (d.iter().fold(0.0, |m: f64, x| m.max(x.abs())), 0.0)
    }
}

#[derive(Clone, Default)]
struct ChanModel {
    last_out: Option<(Vec<f64>, u64)>,
    last_accepted: Option<Vec<f64>>,
}

#[test]
fn randomized_invariants_enforcing() {
    for seed in 1..=SEEDS {
        let mut r = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0xA24B_AED4_963E_E407));
        let cfg = random_cfg(&mut r);
        let mut f = build_cfg(cfg, true);
        assert!(f.fw.is_enforcing());
        let spec = ChannelSpec::default();
        let mut models = [ChanModel::default(), ChanModel::default()];
        let mut now = T0;
        let mut stamps = [T0; 2];

        for step in 0..STEPS {
            // Time mostly advances by a control period; sometimes 0, sometimes a gap.
            now += match r.below(50) {
                0 => 0,
                1 => 800 * MS,
                _ => r.below(60) * MS,
            };
            let on_arm = r.chance(0.3);
            let ch = if on_arm { f.arm } else { f.base };
            let src = match r.below(40) {
                0 => SourceId::UNKNOWN,
                1 => SourceId(r.below(400) as u16),
                2 => {
                    if on_arm {
                        f.nav
                    } else {
                        f.arm_src
                    }
                }
                _ => {
                    if on_arm {
                        f.arm_src
                    } else if r.chance(0.5) {
                        f.nav
                    } else {
                        f.teleop
                    }
                }
            };
            let si = usize::from(on_arm);
            stamps[si] = stamps[si].max(now.saturating_sub(spec.max_age_ns)) + 1;
            let stamp = match r.below(40) {
                0 => now.saturating_sub(spec.max_age_ns + 1 + r.below(1_000) * MS),
                1 => now + spec.max_future_ns + 1 + r.below(1_000),
                2 => stamps[si].saturating_sub(r.below(3)), // replay-ish
                3 => u64::MAX,
                _ => stamps[si].max(now.saturating_sub(5 * MS)),
            };
            stamps[si] = stamps[si].max(stamp.min(now + spec.max_future_ns));
            let cmd = if on_arm {
                let n = if r.chance(0.02) {
                    r.below(MAX_JOINTS as u64 + 1) as usize
                } else {
                    ARM_JOINTS
                };
                let j: Vec<f64> = (0..n).map(|_| value(&mut r, JOINT)).collect();
                joint_cmd(src, ch, stamp, &j)
            } else if r.chance(0.01) {
                joint_cmd(src, ch, stamp, &[0.0; ARM_JOINTS])
            } else {
                let mut c = [0.0; 6];
                for (i, x) in c.iter_mut().enumerate() {
                    *x = value(&mut r, if i < 3 { LIN } else { ANG });
                }
                twist_cmd(src, ch, stamp, tw(c[0], c[1], c[2], c[3], c[4], c[5]))
            };

            let v = f.fw.check(&cmd, now);
            let m = &mut models[si];
            let ctx = || format!("seed {seed} step {step}: {cmd:?} -> {v:?}");

            // Universal: whatever is emitted is finite and within the envelope.
            if let Some(out) = v.output() {
                assert!(out.motion.is_finite(), "{}", ctx());
                assert!(within_speed(&out.motion), "{}", ctx());
                assert_eq!(out.channel, cmd.channel, "{}", ctx());
            }

            match v {
                Verdict::Passed {
                    cmd: out,
                    would_have,
                } => {
                    assert!(would_have.is_none(), "{}", ctx());
                    assert_eq!(out, cmd, "Passed must be bit-exact: {}", ctx());
                }
                Verdict::Limited { cmd: out, reasons } => {
                    assert!(!reasons.is_empty(), "{}", ctx());
                    assert_eq!((out.source, out.stamp_ns), (cmd.source, cmd.stamp_ns));
                }
                Verdict::Rejected { reason, substitute } => {
                    if let Some(s) = substitute {
                        assert_eq!(s.cmd.source, SourceId::FIREWALL, "{}", ctx());
                        assert_eq!(s.cmd.stamp_ns, now, "{}", ctx());
                        let sv = raw(&s.cmd.motion);
                        match s.kind {
                            SubstituteKind::Zero => {
                                assert!(s.cmd.motion.is_zero(), "{}", ctx())
                            }
                            SubstituteKind::HoldLast => assert_eq!(
                                Some(&sv),
                                m.last_accepted.as_ref(),
                                "hold must repeat the last accepted output: {}",
                                ctx()
                            ),
                        }
                    } else {
                        assert!(
                            reason == RejectReason::UnknownChannel
                                || (reason.is_foreign_source()
                                    && cfg.platform.foreign_source_action
                                        == ForeignSourceAction::Drop),
                            "{}",
                            ctx()
                        );
                    }
                }
            }

            // Who and what may never get through.
            if v.is_passed() || v.is_limited() {
                assert_ne!(cmd.source, SourceId::UNKNOWN, "{}", ctx());
                assert!(cmd.motion.is_finite(), "{}", ctx());
                assert!(now - cmd.stamp_ns.min(now) <= spec.max_age_ns, "{}", ctx());
                assert!(cmd.stamp_ns <= now + spec.max_future_ns, "{}", ctx());
            }

            // Accepted output lies between prev, 0 and the input (componentwise)
            // and respects the acceleration bound unless it only decelerates.
            if let (true, Some(out)) = (v.is_passed() || v.is_limited(), v.output()) {
                let o = raw(&out.motion);
                let i = raw(&cmd.motion);
                let (prev, dt_ns) = match &m.last_out {
                    Some((p, at)) if now - at <= spec.state_reset_after_ns => {
                        (p.clone(), (now - at).min(spec.dynamics_dt_cap_ns))
                    }
                    _ => (vec![0.0; o.len()], spec.dynamics_dt_cap_ns),
                };
                for ((oi, pi), ii) in o.iter().zip(&prev).zip(&i) {
                    let lo = pi.min(*ii).min(0.0);
                    let hi = pi.max(*ii).max(0.0);
                    let eps = 1e-12 * (1.0 + lo.abs().max(hi.abs()));
                    assert!(
                        *oi >= lo - eps && *oi <= hi + eps,
                        "output outside [prev, 0, input] hull: {}",
                        ctx()
                    );
                }
                let decel = decelerates(&prev, &o);
                let skip = decel && !cfg.limit_decel;
                if !skip {
                    let dt = dt_ns as f64 * 1e-9;
                    let (s0, s1) = step_mags(&prev, &o, !on_arm);
                    let (a0, a1) = if on_arm {
                        (cfg.joint_acc, None)
                    } else {
                        (cfg.lin_acc, cfg.ang_acc)
                    };
                    if let Some(a) = a0 {
                        assert!(s0 <= a * dt * (1.0 + 1e-9) + 1e-12, "accel 0: {}", ctx());
                    }
                    if let Some(a) = a1 {
                        assert!(s1 <= a * dt * (1.0 + 1e-9) + 1e-12, "accel 1: {}", ctx());
                    }
                }
                m.last_accepted = Some(o.clone());
                m.last_out = Some((o, now));
            } else if let Verdict::Rejected {
                substitute: Some(s),
                ..
            } = v
            {
                m.last_out = Some((raw(&s.cmd.motion), now));
            }
        }

        let s = f.fw.stats();
        assert_eq!(s.passed + s.limited + s.rejected, s.checked, "seed {seed}");
        assert_eq!(s.faults, 0, "seed {seed}: unexpected internal fault");
        assert!(
            s.passed > 0 && s.limited > 0 && s.rejected > 0,
            "seed {seed}: {s:?}"
        );
        // Draining always works and yields firewall rules only.
        for d in f.fw.drain_deviations() {
            assert!(d.rule.starts_with("robot.firewall."));
        }
    }
}

#[test]
fn randomized_observe_mode_always_passes_input() {
    for seed in 1..=SEEDS {
        let mut r = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let cfg = random_cfg(&mut r);
        let mut f = build_cfg(cfg, false);
        let mut now = T0;
        for _ in 0..5_000 {
            now += r.below(30) * MS;
            let src = if r.chance(0.1) {
                SourceId::UNKNOWN
            } else {
                f.nav
            };
            let c: Vec<f64> = (0..6).map(|_| value(&mut r, LIN)).collect();
            let cmd = twist_cmd(
                src,
                f.base,
                now.saturating_sub(r.below(400) * MS),
                tw(c[0], c[1], c[2], c[3], c[4], c[5]),
            );
            let v = f.fw.check(&cmd, now);
            let Verdict::Passed {
                cmd: out,
                would_have,
            } = v
            else {
                panic!("observe mode must pass: {v:?}")
            };
            // Bit-exact including NaN payloads.
            assert_eq!(
                raw(&out.motion)
                    .iter()
                    .map(|x| x.to_bits())
                    .collect::<Vec<_>>(),
                raw(&cmd.motion)
                    .iter()
                    .map(|x| x.to_bits())
                    .collect::<Vec<_>>()
            );
            if let Some(WouldHave::Limited { cmd: lim, .. }) = would_have {
                assert!(within_speed(&lim.motion));
                assert!(lim.motion.is_finite());
            }
            if src == SourceId::UNKNOWN || !cmd.motion.is_finite() {
                assert!(matches!(would_have, Some(WouldHave::Rejected { .. })));
            }
        }
        assert_eq!(f.fw.stats().rejected, 0);
        assert_eq!(f.fw.stats().limited, 0);
    }
}

#[test]
fn randomized_scaling_preserves_direction() {
    let mut r = Rng(42);
    for _ in 0..50_000 {
        let mut f = default_fx();
        let t = tw(
            r.range(-2.0, 2.0),
            r.range(-2.0, 2.0),
            r.range(-2.0, 2.0),
            r.range(-4.0, 4.0),
            r.range(-4.0, 4.0),
            r.range(-4.0, 4.0),
        );
        let (nl, na) = (norm3(t.linear), norm3(t.angular));
        let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, t), T0);
        if nl > 2.0 * LIN || na > 2.0 * ANG {
            assert_eq!(v.reject_reason(), Some(RejectReason::OverHardLimit));
            continue;
        }
        let o = out_twist(&v);
        let i = raw(&Motion::Twist(t));
        let ov = raw(&Motion::Twist(o));
        // One common factor s in (0, 1] for all six components.
        let s = ov
            .iter()
            .zip(&i)
            .filter(|(_, x)| x.abs() > 1e-6)
            .map(|(a, b)| a / b)
            .next()
            .unwrap_or(1.0);
        assert!(s > 0.0 && s <= 1.0);
        for (a, b) in ov.iter().zip(&i) {
            assert!(
                (a - s * b).abs() <= 1e-12 * (1.0 + b.abs()),
                "{t:?} -> {o:?}"
            );
        }
        let expect = (LIN / nl).min(ANG / na).min(1.0);
        assert!((s - expect).abs() < 1e-12, "{s} vs {expect}");
        assert!(norm3(o.linear) <= LIN && norm3(o.angular) <= ANG);
    }
}

#[test]
fn randomized_joint_scaling_never_exceeds_limit() {
    let mut r = Rng(7);
    let mut f = default_fx();
    let mut now = T0;
    for _ in 0..50_000 {
        now += 1;
        let j: Vec<f64> = (0..ARM_JOINTS)
            .map(|_| r.range(-2.0 * JOINT, 2.0 * JOINT))
            .collect();
        let v = f.fw.check(&joint_cmd(f.arm_src, f.arm, now, &j), now);
        let o = out_joints(&v);
        assert!(o.iter().all(|x| x.abs() <= JOINT), "{j:?} -> {o:?}");
        let m = j.iter().fold(0.0f64, |m, x| m.max(x.abs()));
        let s = (JOINT / m).min(1.0);
        for (a, b) in o.iter().zip(&j) {
            assert!((a - s * b).abs() <= 1e-12 * (1.0 + b.abs()));
        }
    }
}
