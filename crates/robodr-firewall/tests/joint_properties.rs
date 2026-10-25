//! Property-style randomized tests of the low-level joint path (std-only
//! xorshift PRNG, fixed seeds so failures reproduce).
//!
//! Random envelopes (1..=35 slots, random enabled set, ranges, gain
//! minimums, hard factors, CRC requirement, rate window, humanoid or
//! quadruped) and random frames (in envelope, in the clamp zone, far out,
//! NaN / inf, Unitree park values, motors off, negative gains, bad CRC,
//! stale / future / replayed / early stamps, foreign sources). Every verdict
//! is checked against an independent reference:
//! - anything forwarded is inside the envelope (naive re-check);
//! - `Passed` is bit-exact; `Limited` only ever lowers `|dq|`, `|tau|`,
//!   `kp`, `kd` (never raises a gain) and projects `q`; mode and unused
//!   slots untouched;
//! - limiting is idempotent: a limited frame passes unchanged;
//! - a substitute is the held last accepted frame (velocity zeroed; on a
//!   humanoid past `max_hold_ns` also `tau` zeroed) or the damping frame,
//!   never a value of the rejected frame, and **never** the damping frame
//!   on a humanoid;
//! - a mode-off slot that carries gains / torque is never forwarded;
//! - forwarded position targets respect `max_dq_step` / `tau_pd_max`
//!   against an independently modelled previous target;
//! - nothing limp (every enabled slot without stiffness and damping) is
//!   ever emitted on a humanoid.

mod common;
use common::*;
use robodr_firewall::*;
use std::collections::BTreeMap;

const SEEDS: u64 = 24;
const STEPS: usize = 4_000;

#[derive(Debug, Clone, Copy)]
struct Lim {
    enabled: bool,
    q: (f64, f64),
    dq: f64,
    tau: f64,
    kp: (f64, f64),
    kd: (f64, f64),
    allow_limp: bool,
    step: Option<f64>,
    pd: Option<f64>,
}

const NO_Q: f64 = f64::NAN;
/// Humanoid `max_hold_ns` (`common::humanoid()`).
const HUMANOID_MAX_HOLD: u64 = 50 * MS;

fn rand_lim(r: &mut Rng, humanoid: bool) -> Lim {
    let lo = r.range(-3.0, 0.5);
    let kp_max = if r.chance(0.1) {
        0.0
    } else {
        r.range(0.0, 300.0)
    };
    let kd_max = r.range(0.0, 10.0);
    Lim {
        enabled: r.chance(0.8),
        q: (lo, lo + r.range(0.0, 5.0)),
        dq: r.range(0.0, 40.0),
        tau: r.range(0.0, 150.0),
        kp: (
            if r.chance(0.3) {
                r.range(0.0, kp_max * 0.3)
            } else {
                0.0
            },
            kp_max,
        ),
        kd: (
            if r.chance(0.3) {
                r.range(0.0, kd_max * 0.3)
            } else {
                0.0
            },
            kd_max,
        ),
        // A humanoid needs a non-zero minimum or an explicit opt-in; the
        // opt-in is set below where both minimums are zero.
        allow_limp: false,
        step: (humanoid || r.chance(0.5)).then(|| r.range(0.05, 2.0)),
        pd: r.chance(0.3).then(|| r.range(1.0, 100.0)),
    }
}

fn to_spec(l: &Lim) -> MotorLimits {
    if !l.enabled {
        return MotorLimits::disabled();
    }
    MotorLimits {
        kp_min: l.kp.0,
        kd_min: l.kd.0,
        allow_limp: l.allow_limp,
        max_dq_step: l.step,
        tau_pd_max: l.pd,
        ..MotorLimits::enabled(l.q, l.dq, l.tau, l.kp.1, l.kd.1)
    }
}

/// Independent envelope check (`dq_env` = envelope max_joint_speed;
/// `q_prev` = modelled previous position target, NaN if none).
fn ref_motor_ok(m: &MotorCmd, l: &Lim, dq_env: f64, q_prev: f64) -> bool {
    let finite = [m.q, m.dq, m.tau, m.kp, m.kd].iter().all(|x| x.is_finite());
    if !finite {
        return false;
    }
    let on = m.mode == MotorMode::Enabled;
    if !on && (m.kp != 0.0 || m.kd != 0.0 || m.tau != 0.0) {
        return false;
    }
    if !l.enabled {
        return !(on && (m.kp != 0.0 || m.kd != 0.0 || m.tau != 0.0));
    }
    let (kp, kd) = if on { (m.kp, m.kd) } else { (0.0, 0.0) };
    if kp < l.kp.0 || kd < l.kd.0 {
        return false;
    }
    if !on {
        return true;
    }
    let base = kp <= l.kp.1
        && kd <= l.kd.1
        && m.tau.abs() <= l.tau
        && (kd == 0.0 || m.dq.abs() <= l.dq.min(dq_env))
        && (kp == 0.0 || (l.q.0 <= m.q && m.q <= l.q.1));
    if !base {
        return false;
    }
    if kp > 0.0 && q_prev.is_finite() {
        // Rounding of `q_prev ± step` only.
        let d = (m.q - q_prev).abs();
        let eps = 1e-9;
        if l.step.is_some_and(|s| d > s + eps) {
            return false;
        }
        if l.pd.is_some_and(|t| kp * d > t + kp * eps) {
            return false;
        }
    }
    true
}

fn ref_frame_ok(f: &JointFrame, lims: &[Lim], dq_env: f64, q_prev: &[f64]) -> bool {
    f.slots() == lims.len()
        && f.motors()
            .iter()
            .zip(lims)
            .zip(q_prev)
            .all(|((m, l), q)| ref_motor_ok(m, l, dq_env, *q))
}

/// Every enabled slot without stiffness and damping (and at least one).
fn ref_all_limp(f: &JointFrame, lims: &[Lim]) -> bool {
    lims.iter().any(|l| l.enabled)
        && f.motors()
            .iter()
            .zip(lims)
            .filter(|(_, l)| l.enabled)
            .all(|(m, _)| m.mode == MotorMode::Disabled || (m.kp == 0.0 && m.kd == 0.0))
}

/// The modelled previous position targets after `out` was accepted.
fn next_q_prev(out: &JointFrame) -> [f64; MAX_MOTORS] {
    let mut q = [NO_Q; MAX_MOTORS];
    for (dst, m) in q.iter_mut().zip(out.motors()) {
        if m.mode == MotorMode::Enabled && m.kp > 0.0 {
            *dst = m.q;
        }
    }
    q
}

fn rand_motor(r: &mut Rng, l: &Lim) -> MotorCmd {
    let inside = |r: &mut Rng| {
        MotorCmd::enabled(
            r.range(l.q.0, l.q.1),
            r.range(-l.dq, l.dq),
            r.range(-l.tau, l.tau),
            r.range(l.kp.0, l.kp.1),
            r.range(l.kd.0, l.kd.1),
        )
    };
    match r.below(100) {
        0..=59 => inside(r),
        60..=79 => {
            // Clamp zone: one or more fields up to 1.6x their bound.
            let mut m = inside(r);
            let s = r.range(1.0, 1.6);
            match r.below(5) {
                0 => {
                    m.q = if r.chance(0.5) {
                        l.q.1 + 0.3
                    } else {
                        l.q.0 - 0.3
                    }
                }
                1 => m.dq = l.dq * s * if r.chance(0.5) { 1.0 } else { -1.0 },
                2 => m.tau = l.tau * s * if r.chance(0.5) { 1.0 } else { -1.0 },
                3 => m.kp = l.kp.1 * s,
                _ => m.kd = l.kd.1 * s,
            }
            m
        }
        80..=86 => {
            // Far out.
            let mut m = inside(r);
            match r.below(5) {
                0 => m.q = 1e3,
                1 => m.dq = -1e4,
                2 => m.tau = 1e5,
                3 => m.kp = 1e4,
                _ => m.kd = 1e3,
            }
            m
        }
        87..=89 => MotorCmd::enabled(2.146e9, 16000.0, 0.0, 0.0, 0.0), // Unitree park
        90..=92 => MotorCmd::OFF,
        93..=94 => MotorCmd {
            kp: -r.range(0.0, 10.0),
            ..inside(r)
        },
        95 => MotorCmd {
            q: f64::NAN,
            ..inside(r)
        },
        96 => MotorCmd {
            tau: f64::INFINITY,
            ..inside(r)
        },
        97 => MotorCmd {
            kd: f64::MAX,
            ..inside(r)
        },
        98 => MotorCmd {
            // Mode off but loaded.
            kp: r.range(0.0, 50.0),
            tau: r.range(0.0, 5.0),
            ..MotorCmd::OFF
        },
        _ => MotorCmd::enabled(0.0, 0.0, r.range(0.0, 1.0), 0.0, 0.0),
    }
}

/// Mostly a frame of the right shape; unused slots usually OFF.
fn rand_frame(r: &mut Rng, lims: &[Lim]) -> JointFrame {
    let mut ms: Vec<MotorCmd> = lims
        .iter()
        .map(|l| {
            if l.enabled || r.chance(0.02) {
                rand_motor(r, l)
            } else if r.chance(0.3) {
                MotorCmd::enabled(2.146e9, 16000.0, 0.0, 0.0, 0.0)
            } else {
                MotorCmd::OFF
            }
        })
        .collect();
    if r.chance(0.01) {
        ms.pop();
    }
    // Keep most frames clean so the accept paths run often.
    if r.chance(0.6) {
        for (m, l) in ms.iter_mut().zip(lims) {
            if l.enabled && !ref_motor_ok(m, l, ENV_DQ, NO_Q) && r.chance(0.8) {
                *m = MotorCmd::enabled(
                    (l.q.0 + l.q.1) / 2.0,
                    0.0,
                    0.0,
                    (l.kp.0 + l.kp.1) / 2.0,
                    (l.kd.0 + l.kd.1) / 2.0,
                );
            }
        }
    }
    let crc = match r.below(100) {
        0 => Some(false),
        1 => None,
        _ => Some(true),
    };
    JointFrame::from_slice(&ms, crc).unwrap_or_else(|| JointFrame::new(0, crc).unwrap())
}

struct Setup {
    policy: Policy,
    lims: Vec<Lim>,
    humanoid: bool,
    damping_kd: f64,
}

fn setup(r: &mut Rng, locked: bool) -> Setup {
    let slots = 1 + r.below(MAX_MOTORS as u64) as usize;
    let humanoid = r.chance(0.5);
    let lims: Vec<Lim> = (0..slots)
        .map(|_| {
            let mut l = rand_lim(r, humanoid);
            if humanoid && l.kp.0 == 0.0 && l.kd.0 == 0.0 {
                // Either an explicit opt-in or a damping minimum.
                if r.chance(0.5) || l.kd.1 == 0.0 {
                    l.allow_limp = true;
                } else {
                    l.kd.0 = l.kd.1 * 0.1;
                }
            }
            l
        })
        .collect();
    let platform = if humanoid {
        // FailOpen / FailSafe are refused for a humanoid joint channel.
        common::humanoid()
    } else {
        quadruped(if r.chance(0.5) {
            FailBehaviour::ZeroVelocity
        } else {
            FailBehaviour::HoldLast {
                max_hold_ns: r.below(100) * MS,
            }
        })
    };
    let platform = PlatformConfig {
        foreign_source_action: if r.chance(0.5) {
            ForeignSourceAction::Drop
        } else {
            ForeignSourceAction::Substitute
        },
        event_capacity: 32,
        ..platform
    };
    let damping_kd = r.range(0.0, 4.0);
    let spec = JointChannelSpec {
        allowed_sources: vec![guid("00000103")],
        motors: lims.iter().map(to_spec).collect(),
        require_crc: r.chance(0.7),
        rate: Some(if r.chance(0.5) {
            JointRate::around(1000.0)
        } else {
            wide_rate()
        }),
        hard_reject_factor: r.range(1.0, 3.0),
        damping_kd,
        ..Default::default()
    };
    let policy = Policy::compile_with_joints(
        &joint_profile(locked),
        platform,
        &twist_specs(),
        &BTreeMap::from([("/lowcmd".to_string(), spec)]),
    )
    .expect("random config compiles");
    Setup {
        policy,
        lims,
        humanoid,
        damping_kd,
    }
}

fn held(f: &JointFrame, drop_tau: bool) -> JointFrame {
    let mut h = *f;
    for i in 0..h.slots() {
        let m = h.motor_mut(i).unwrap();
        m.dq = 0.0;
        if drop_tau {
            m.tau = 0.0;
        }
    }
    h.crc_ok = Some(true);
    h
}

fn check_limited(input: &JointFrame, out: &JointFrame, lims: &[Lim], q_prev: &[f64]) {
    assert_eq!(input.slots(), out.slots());
    for (((a, b), l), qp) in input
        .motors()
        .iter()
        .zip(out.motors())
        .zip(lims)
        .zip(q_prev)
    {
        assert_eq!(a.mode, b.mode);
        if !l.enabled || a.mode == MotorMode::Disabled {
            assert_eq!(a, b, "untouched slot changed");
            continue;
        }
        // Magnitudes never grow; signs never flip; gains never rise.
        assert!(
            b.dq.abs() <= a.dq.abs() && b.dq * a.dq >= 0.0,
            "{a:?} {b:?}"
        );
        assert!(
            b.tau.abs() <= a.tau.abs() && b.tau * a.tau >= 0.0,
            "{a:?} {b:?}"
        );
        assert!(b.kp <= a.kp && b.kp >= 0.0, "{a:?} {b:?}");
        assert!(b.kd <= a.kd && b.kd >= 0.0, "{a:?} {b:?}");
        // q is projected onto its range (only when kp acts), then moved
        // toward the previous target if the step bounds require it: it
        // always lies between the two.
        if a.kp > 0.0 {
            let proj = a.q.clamp(l.q.0, l.q.1);
            if qp.is_finite() {
                assert!(
                    b.q >= proj.min(*qp) && b.q <= proj.max(*qp),
                    "{a:?} {b:?} prev {qp}"
                );
            } else {
                assert_eq!(b.q, proj);
            }
        } else {
            assert_eq!(b.q, a.q);
        }
    }
}

fn run(seed: u64, locked: bool) -> [u64; 6] {
    let mut r = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x1234_5678_9ABC_DEF1));
    let s = setup(&mut r, locked);
    let mut fw = Firewall::new(s.policy.clone());
    let ctl = fw.source_id(&guid("00000103")).unwrap();
    let nav = fw.source_id(&guid("00000203")).unwrap();
    let low = fw.channel_id("/lowcmd").unwrap();
    let mut now = T0;
    let mut last_stamp = T0;
    let mut last_out: Option<(JointFrame, u64)> = None;
    let mut q_prev = [NO_Q; MAX_MOTORS];
    let mut counts = [0u64; 6];
    for step in 0..STEPS {
        now += match r.below(100) {
            0..=2 => r.below(400_000),          // early
            3..=4 => 5 * MS + r.below(50 * MS), // gap
            _ => 900_000 + r.below(200_000),    // 1 kHz +- 100 us
        };
        let stamp = match r.below(100) {
            0 => now.saturating_sub(100 * MS), // stale
            1 => now + 50 * MS,                // future
            2 => last_stamp,                   // replay
            _ => now - r.below(MS),
        };
        let src = match r.below(100) {
            0 => SourceId::UNKNOWN,
            1 => nav,
            _ => ctl,
        };
        let cmd = JointCommand::new(src, low, stamp, rand_frame(&mut r, &s.lims));
        let at = if r.chance(0.002) { now - 1 } else { now }; // clock regression
        let v = fw.check_joint(&cmd, at);
        if !locked {
            // Bit-exact (Debug, because NaN != NaN).
            assert!(
                matches!(v, JointVerdict::Passed { cmd: c, .. } if format!("{c:?}") == format!("{cmd:?}")),
                "seed {seed} step {step}: observe mode must forward: {v:?}"
            );
            counts[0] += 1;
            continue;
        }
        let ctx = format!("seed {seed} step {step}: {v:?}");
        match v {
            JointVerdict::Passed {
                cmd: out,
                would_have,
            } => {
                assert_eq!(out, cmd, "{ctx}");
                assert!(would_have.is_none(), "{ctx}");
                assert!(ref_frame_ok(&out.frame, &s.lims, ENV_DQ, &q_prev), "{ctx}");
                assert!(!(s.humanoid && ref_all_limp(&out.frame, &s.lims)), "{ctx}");
                assert!(src == ctl && out.frame.crc_ok != Some(false), "{ctx}");
                last_out = Some((out.frame, at));
                q_prev = next_q_prev(&out.frame);
                last_stamp = stamp;
                counts[0] += 1;
            }
            JointVerdict::Limited { cmd: out, reasons } => {
                assert!(!reasons.is_empty(), "{ctx}");
                assert!(ref_frame_ok(&out.frame, &s.lims, ENV_DQ, &q_prev), "{ctx}");
                assert!(!(s.humanoid && ref_all_limp(&out.frame, &s.lims)), "{ctx}");
                check_limited(&cmd.frame, &out.frame, &s.lims, &q_prev);
                assert_eq!((out.source, out.channel, out.stamp_ns), (ctl, low, stamp));
                // Idempotent: the limited frame passes unchanged.
                let mut fresh = Firewall::new(s.policy.clone());
                let again = JointCommand::new(ctl, low, stamp, out.frame);
                assert_eq!(
                    fresh.check_joint(&again, at),
                    JointVerdict::Passed {
                        cmd: again,
                        would_have: None
                    },
                    "{ctx}"
                );
                last_out = Some((out.frame, at));
                q_prev = next_q_prev(&out.frame);
                last_stamp = stamp;
                counts[1] += 1;
                if reasons.contains(JointLimitReasons::STEP)
                    || reasons.contains(JointLimitReasons::PD_TORQUE)
                {
                    counts[4] += 1;
                }
            }
            JointVerdict::Rejected { reason, substitute } => {
                counts[2] += 1;
                if matches!(
                    reason,
                    RejectReason::JointStepOutOfEnvelope | RejectReason::JointPdTorqueOutOfEnvelope
                ) {
                    counts[5] += 1;
                }
                let Some(sub) = substitute else { continue };
                assert_eq!(sub.cmd.source, SourceId::FIREWALL, "{ctx}");
                assert_eq!(sub.cmd.stamp_ns, at, "{ctx}");
                assert_ne!(reason, RejectReason::RateLimited, "{ctx}");
                match sub.kind {
                    SubstituteKind::HoldLast => {
                        let (base, base_at) = last_out.expect("hold without an accepted frame");
                        let drop_tau = s.humanoid && at.saturating_sub(base_at) > HUMANOID_MAX_HOLD;
                        assert_eq!(sub.cmd.frame, held(&base, drop_tau), "{ctx}");
                        assert!(
                            !(s.humanoid && ref_all_limp(&sub.cmd.frame, &s.lims)),
                            "{ctx}"
                        );
                    }
                    SubstituteKind::Zero => {
                        assert!(!s.humanoid, "humanoid got a damping frame: {ctx}");
                        counts[3] += 1;
                        // The motors were released: no previous target.
                        q_prev = [NO_Q; MAX_MOTORS];
                        for (m, l) in sub.cmd.frame.motors().iter().zip(&s.lims) {
                            if l.enabled {
                                assert_eq!(
                                    *m,
                                    MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, s.damping_kd.min(l.kd.1)),
                                    "{ctx}"
                                );
                            } else {
                                assert_eq!(*m, MotorCmd::OFF, "{ctx}");
                            }
                        }
                    }
                }
                // Whatever is emitted never energises an unused slot.
                for (m, l) in sub.cmd.frame.motors().iter().zip(&s.lims) {
                    assert!(l.enabled || !m.energises(), "{ctx}");
                }
            }
        }
        if step % 64 == 0 {
            fw.drain_events(|_| {});
        }
    }
    counts
}

#[test]
fn randomized_joint_invariants_enforcing() {
    let mut total = [0u64; 6];
    for seed in 0..SEEDS {
        let c = run(seed, true);
        for (t, x) in total.iter_mut().zip(c) {
            *t += x;
        }
    }
    // Every path was taken many times overall.
    eprintln!(
        "joint property totals [passed, limited, rejected, damped, step-limited, step-rejected]: {total:?}"
    );
    let [passed, limited, rejected, damped, step_limited, step_rejected] = total;
    assert!(step_limited > 100, "{total:?}");
    assert!(step_rejected > 100, "{total:?}");
    assert!(passed > 1_000, "{total:?}");
    assert!(limited > 1_000, "{total:?}");
    assert!(rejected > 1_000, "{total:?}");
    assert!(damped > 50, "{total:?}");
}

#[test]
fn randomized_joint_observe_mode_always_forwards() {
    for seed in 0..4 {
        run(seed, false);
    }
}

#[test]
fn clamping_is_idempotent_and_never_increases_magnitude_exhaustive_edges() {
    // Deterministic edge cases on one slot: every field at -2x, -1x-eps,
    // -1x, 0, +1x, +1x+eps, +2x of its bound (hard factor 3 so nothing is
    // rejected for being far out).
    // (Quadruped: a lone slot with zero gains would be a limp frame on a
    // humanoid.)
    let mut f = build_joint(quadruped(FailBehaviour::ZeroVelocity), true, 1, 1, |s| {
        s.hard_reject_factor = 3.0
    });
    let lim = Lim {
        enabled: true,
        q: (-Q_LIM, Q_LIM),
        dq: DQ_MAX,
        tau: TAU_MAX,
        kp: (0.0, KP_MAX),
        kd: (0.0, KD_MAX),
        allow_limp: true,
        step: Some(STEP_MAX),
        pd: None,
    };
    let mults = [-2.0, -1.0 - 1e-12, -1.0, 0.0, 1.0, 1.0 + 1e-12, 2.0];
    let mut t = T0;
    let mut n = 0;
    for &a in &mults {
        for &b in &mults {
            for &c in &mults {
                for &(kp, kd) in &[(0.0, 0.0), (KP_MAX * 1.5, 1.0), (10.0, KD_MAX * 2.0)] {
                    let m = MotorCmd::enabled(a * Q_LIM, b * DQ_MAX, c * TAU_MAX, kp, kd);
                    let input = JointFrame::from_slice(&[m], Some(true)).unwrap();
                    t += MS;
                    let v =
                        f.fw.check_joint(&JointCommand::new(f.ctl, f.low, t, input), t);
                    let out = jout(&v);
                    assert!(!v.is_rejected(), "{m:?}: {v:?}");
                    assert!(ref_frame_ok(&out, &[lim], ENV_DQ, &[NO_Q]), "{m:?}");
                    if v.is_limited() {
                        check_limited(&input, &out, &[lim], &[NO_Q]);
                        t += MS;
                        let again =
                            f.fw.check_joint(&JointCommand::new(f.ctl, f.low, t, out), t);
                        assert!(again.is_passed(), "not idempotent: {m:?}");
                        assert_eq!(jout(&again), out);
                    } else {
                        assert_eq!(out, input);
                    }
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, 7 * 7 * 7 * 3);
}
