//! Regressions for the independent review of the low-level joint-frame path
//! (findings F1-F10). Each test failed before its fix.

mod common;
use common::*;
use robodr_events::Severity;
use robodr_firewall::*;

const T: u64 = T0;

fn reason(v: &JointVerdict) -> RejectReason {
    v.reject_reason()
        .unwrap_or_else(|| panic!("not rejected: {v:?}"))
}

fn events(fw: &mut Firewall) -> Vec<FirewallEvent> {
    let mut out = Vec::new();
    fw.drain_events(|e| out.push(*e));
    out
}

fn qp() -> PlatformConfig {
    quadruped(FailBehaviour::ZeroVelocity)
}

fn compile(platform: PlatformConfig, spec: JointChannelSpec) -> Result<Policy, ConfigError> {
    Policy::compile_with_joints(
        &joint_profile(true),
        platform,
        &twist_specs(),
        &joint_specs(spec),
    )
}

fn at(f: &JFx, stamp: u64, m: impl Fn(usize) -> MotorCmd) -> JointCommand {
    JointCommand::new(f.ctl, f.low, stamp, jframe(f.slots, f.active, m))
}

// ------------------------------------------------------------------ F1

#[test]
fn f1_any_nonzero_mode_octet_is_enabled() {
    assert_eq!(MotorMode::from_u8(0x00), MotorMode::Disabled);
    for b in [0x01u8, 0x0A, 0x02, 0x80, 0xFF] {
        assert_eq!(MotorMode::from_u8(b), MotorMode::Enabled, "{b:#04x}");
        assert_eq!(MotorMode::from(b), MotorMode::Enabled, "{b:#04x}");
    }
    assert_eq!(MotorMode::from(0u8), MotorMode::Disabled);
    // A B2 / H1 strong-motor slot (mode 0x0A) is checked like any enabled
    // slot: a gain far over its bound is rejected, not forwarded.
    let mut f = build_joint(qp(), true, 20, 12, |_| {});
    let m = MotorCmd {
        mode: MotorMode::from_u8(0x0A),
        ..MotorCmd::enabled(0.0, 0.0, 0.0, 1e6, 1.0)
    };
    let v = f.fw.check_joint(&f.with_slot(T, 2, m), T);
    assert_eq!(reason(&v), RejectReason::JointGainOutOfEnvelope);
}

#[test]
fn f1_disabled_mode_slot_carrying_gains_or_torque_is_rejected() {
    let mut f = build_joint(qp(), true, 20, 12, |_| {});
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    let mut t = T;
    // Slot 2 is enabled in the envelope (kp_min = kd_min = 0), slot 15 is
    // unused. Mode off but kp / kd / tau set (even absurd values): the
    // values never leave the firewall unchecked.
    for slot in [2usize, 15] {
        for m in [
            MotorCmd {
                kp: 80.0,
                ..MotorCmd::OFF
            },
            MotorCmd {
                kd: 1.0,
                ..MotorCmd::OFF
            },
            MotorCmd {
                tau: 3.0,
                ..MotorCmd::OFF
            },
            MotorCmd {
                kp: 1e9,
                q: 1e9,
                ..MotorCmd::OFF
            },
        ] {
            t += MS;
            let v = f.fw.check_joint(&f.with_slot(t, slot, m), t);
            assert_eq!(
                reason(&v),
                RejectReason::JointModeInconsistent,
                "slot {slot} {m:?}"
            );
        }
    }
    let ev = events(&mut f.fw);
    assert!(ev
        .iter()
        .all(|e| e.rule == rules::JOINT_MODE_INCONSISTENT && e.severity == Severity::Critical));
    // Mode off with every gain and torque zero is inert: allowed on an
    // enabled slot whose minimums are zero, and on an unused slot.
    for slot in [2usize, 15] {
        t += MS;
        let m = MotorCmd {
            q: 2.146e9,
            dq: 16000.0,
            ..MotorCmd::OFF
        };
        assert!(f.fw.check_joint(&f.with_slot(t, slot, m), t).is_passed());
    }
}

// ------------------------------------------------------------------ F2

#[test]
fn f2_humanoid_refuses_a_limp_capable_slot_unless_allow_limp() {
    let limp_slot = |allow: bool| {
        let mut s = joint_spec(12, 12);
        let m = &mut s.motors[3];
        m.kp_min = 0.0;
        m.kd_min = 0.0;
        m.allow_limp = allow;
        s
    };
    let e = compile(humanoid(), limp_slot(false)).unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::InvalidMotorLimit {
                slot: 3,
                field: "kp_min",
                ..
            }
        ),
        "{e:?}"
    );
    assert!(e.to_string().contains("allow_limp"), "{e}");
    assert!(compile(humanoid(), limp_slot(true)).is_ok());
    // A non-zero minimum on either gain is enough.
    let mut s = limp_slot(false);
    s.motors[3].kd_min = 0.2;
    assert!(compile(humanoid(), s).is_ok());
    // Not a humanoid: no requirement.
    assert!(compile(qp(), limp_slot(false)).is_ok());
}

#[test]
fn f2_humanoid_all_limp_frame_is_rejected_and_the_last_frame_held() {
    let limp_frames: [fn(usize) -> MotorCmd; 3] = [
        |_| MotorCmd::OFF,
        |_| MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, 0.0),
        // Feed-forward torque only: no stiffness, no damping anywhere.
        |_| MotorCmd::enabled(0.0, 0.0, 1.0, 0.0, 0.0),
    ];
    for (i, limp) in limp_frames.into_iter().enumerate() {
        let mut f = build_joint(humanoid(), true, 20, 12, |_| {});
        let first = f.nominal(T);
        assert!(f.fw.check_joint(&first, T).is_passed());
        let v = f.fw.check_joint(&at(&f, T + MS, limp), T + MS);
        assert_eq!(reason(&v), RejectReason::JointLimpFrame, "case {i}");
        let sub = v.output().expect("held");
        assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
        assert_eq!(sub.frame.motor(0).unwrap().kp, good().kp);
        let ev = events(&mut f.fw);
        assert_eq!(ev[0].rule, rules::JOINT_LIMP_FRAME);
        assert_eq!(ev[0].severity, Severity::Critical);
        // One slot with a gain is enough to not be limp.
        let mut c = at(&f, T + 2 * MS, limp);
        *c.frame.motor_mut(5).unwrap() = good();
        assert!(!f.fw.check_joint(&c, T + 2 * MS).is_rejected(), "case {i}");
        // A quadruped may fold down: the same frame passes there.
        let mut q = build_joint(qp(), true, 20, 12, |_| {});
        assert!(!q.fw.check_joint(&at(&q, T, limp), T).is_rejected());
    }
}

#[test]
fn f2_g1_example_has_no_limp_capable_slot() {
    let cfg = FirewallConfig::from_json(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/firewall.unitree-g1.example.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for (name, ch) in &cfg.joint_channels {
        for (i, m) in ch.motors.iter().enumerate().filter(|(_, m)| m.enabled) {
            assert!(
                m.kp_min > 0.0 || m.kd_min > 0.0,
                "{name} slot {i} ({:?}) can be limp",
                m.name
            );
            assert!(!m.allow_limp, "{name} slot {i}");
            assert!(m.max_dq_step.is_some(), "{name} slot {i}");
        }
    }
}

// ------------------------------------------------------------------ F3

/// A quadruped that holds (so a rejection keeps the step reference).
fn holding_qp() -> PlatformConfig {
    quadruped(FailBehaviour::HoldLast {
        max_hold_ns: 1_000 * MS,
    })
}

fn stepped_on(platform: PlatformConfig, step: Option<f64>, pd: Option<f64>) -> JFx {
    build_joint(platform, true, 12, 12, |s| {
        for m in &mut s.motors {
            m.max_dq_step = step;
            m.tau_pd_max = pd;
        }
    })
}

fn stepped(step: Option<f64>, pd: Option<f64>) -> JFx {
    stepped_on(qp(), step, pd)
}

fn q_at(f: &JFx, stamp: u64, q: f64) -> JointCommand {
    f.with_slot(stamp, 0, MotorCmd::enabled(q, 0.0, 0.0, 50.0, 1.0))
}

#[test]
fn f3_q_step_is_limited_then_rejected_beyond_the_hard_factor() {
    let mut f = stepped_on(holding_qp(), Some(0.1), None);
    // First frame: no previous q, only the absolute range applies.
    assert!(f.fw.check_joint(&q_at(&f, T, 0.9), T).is_passed());
    let v = f.fw.check_joint(&q_at(&f, T + MS, 0.2), T + MS);
    assert_eq!(reason(&v), RejectReason::JointStepOutOfEnvelope);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    let _ = events(&mut f.fw);
    // Within the hard factor: stepped toward the target by max_dq_step.
    let v = f.fw.check_joint(&q_at(&f, T + 2 * MS, 0.75), T + 2 * MS);
    let JointVerdict::Limited { cmd, reasons } = v else {
        panic!("{v:?}")
    };
    assert_eq!(reasons, JointLimitReasons::STEP);
    assert!((cmd.frame.motor(0).unwrap().q - 0.8).abs() < 1e-12);
    let ev = events(&mut f.fw);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].rule, rules::JOINT_STEP_OUT_OF_ENVELOPE);
    assert_eq!(ev[0].action, EventAction::Limited);
    assert!((ev[0].value - 0.15).abs() < 1e-9 && ev[0].limit == 0.1);
    // The reference is the last accepted (limited) output, 0.8.
    assert!(f
        .fw
        .check_joint(&q_at(&f, T + 3 * MS, 0.71), T + 3 * MS)
        .is_passed());
}

#[test]
fn f3_pd_torque_demand_is_bounded() {
    // kp 50, tau_pd_max 5 N·m: at most 0.1 rad from the previous target.
    let mut f = stepped(None, Some(5.0));
    assert!(f.fw.check_joint(&q_at(&f, T, 0.0), T).is_passed());
    let v = f.fw.check_joint(&q_at(&f, T + MS, 0.15), T + MS);
    let JointVerdict::Limited { cmd, reasons } = v else {
        panic!("{v:?}")
    };
    assert_eq!(reasons, JointLimitReasons::PD_TORQUE);
    assert!((cmd.frame.motor(0).unwrap().q - 0.1).abs() < 1e-12);
    let v = f.fw.check_joint(&q_at(&f, T + 2 * MS, 0.4), T + 2 * MS);
    assert_eq!(reason(&v), RejectReason::JointPdTorqueOutOfEnvelope);
    let ev = events(&mut f.fw);
    assert!(ev
        .iter()
        .any(|e| e.rule == rules::JOINT_PD_TORQUE_OUT_OF_ENVELOPE
            && e.action == EventAction::Limited));
    assert!(ev
        .iter()
        .any(|e| e.rule == rules::JOINT_PD_TORQUE_OUT_OF_ENVELOPE
            && matches!(e.action, EventAction::Rejected(_))));
}

#[test]
fn f3_reference_is_cleared_by_damping_not_by_a_kp_zero_slot() {
    let mut f = stepped(Some(0.1), None);
    assert!(f.fw.check_joint(&q_at(&f, T, 0.0), T).is_passed());
    // A CRC failure: the quadruped damps; the old target is no longer in force.
    let mut bad = q_at(&f, T + MS, 0.0);
    bad.frame.crc_ok = Some(false);
    let v = f.fw.check_joint(&bad, T + MS);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
    assert!(f
        .fw
        .check_joint(&q_at(&f, T + 2 * MS, 0.9), T + 2 * MS)
        .is_passed());
    // A kp = 0 slot holds no position, but the reference stays (gateway
    // review, finding 5: alternating kp = 0 frames used to clear it, so
    // every other frame could jump anywhere in the range). A holding
    // platform, so a rejection does not damp (which would clear it).
    let mut f = stepped_on(holding_qp(), Some(0.1), None);
    assert!(f.fw.check_joint(&q_at(&f, T, 0.0), T).is_passed());
    let free = |f: &JFx, t| f.with_slot(t, 0, MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, 1.0));
    assert!(f.fw.check_joint(&free(&f, T + MS), T + MS).is_passed());
    let v = f.fw.check_joint(&q_at(&f, T + 2 * MS, -0.9), T + 2 * MS);
    assert_eq!(reason(&v), RejectReason::JointStepOutOfEnvelope);
    // It expires by time (`step_reference_ttl_ns`, default 500 ms after the
    // frame that set it, at T).
    assert!(f
        .fw
        .check_joint(&free(&f, T + 400 * MS), T + 400 * MS)
        .is_passed());
    assert_eq!(
        reason(
            &f.fw
                .check_joint(&q_at(&f, T + 450 * MS, -0.9), T + 450 * MS)
        ),
        RejectReason::JointStepOutOfEnvelope
    );
    assert!(f
        .fw
        .check_joint(&free(&f, T + 501 * MS), T + 501 * MS)
        .is_passed());
    assert!(f
        .fw
        .check_joint(&q_at(&f, T + 502 * MS, -0.9), T + 502 * MS)
        .is_passed());
}

/// Gateway review, finding 5: the attack. Every other frame sets the slot
/// to `kp = 0`; each position frame between them jumps by the largest step
/// it can. Before the fix every jump was decided without a step bound.
#[test]
fn gw5_alternating_kp_zero_frames_do_not_lift_the_step_bound() {
    let mut f = stepped_on(holding_qp(), Some(0.1), None);
    assert!(f.fw.check_joint(&q_at(&f, T, 0.0), T).is_passed());
    let mut target = 0.0;
    let mut now = T;
    for k in 0..20 {
        now += MS;
        let free = f.with_slot(now, 0, MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, 1.0));
        assert!(f.fw.check_joint(&free, now).is_passed());
        now += MS;
        // A far jump (hard reject: hold) or one within the hard factor
        // (limited to one step).
        let want = if k % 2 == 0 { 0.9 } else { target + 0.15 };
        let v = f.fw.check_joint(&q_at(&f, now, want), now);
        // Never more than one step from the previous position target.
        // (A hold re-emits the last accepted frame: the kp = 0 one.)
        if let Some(m) = v
            .output()
            .and_then(|o| o.frame.motor(0))
            .filter(|m| m.kp > 0.0)
        {
            assert!(
                (m.q - target).abs() <= 0.1 + 1e-9,
                "k {k}: {} from {target}",
                m.q
            );
            target = m.q;
        }
    }
}

#[test]
fn f3_max_dq_step_is_required_on_humanoid_enabled_slots() {
    let mut s = joint_spec(12, 12);
    s.motors[4].max_dq_step = None;
    let e = compile(humanoid(), s.clone()).unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::InvalidMotorLimit {
                slot: 4,
                field: "max_dq_step",
                ..
            }
        ),
        "{e:?}"
    );
    assert!(compile(qp(), s).is_ok());
    for (field, bad) in [
        ("max_dq_step", 0.0),
        ("max_dq_step", -1.0),
        ("tau_pd_max", 0.0),
    ] {
        let mut s = joint_spec(12, 12);
        if field == "max_dq_step" {
            s.motors[1].max_dq_step = Some(bad);
        } else {
            s.motors[1].tau_pd_max = Some(bad);
        }
        let e = compile(qp(), s).unwrap_err();
        assert!(
            matches!(e, ConfigError::InvalidMotorLimit { slot: 1, field: f, .. } if f == field),
            "{e:?}"
        );
    }
}

// ------------------------------------------------------------------ F4

#[test]
fn f4_a_flood_of_rejected_frames_is_not_a_flood_of_substitutes() {
    for platform in [humanoid(), qp()] {
        let mut f = build_joint(platform, true, 12, 12, |s| {
            s.rate = Some(JointRate::around(500.0)); // min interval 1 ms
        });
        assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
        let mut emitted = 0;
        let mut rejected = 0;
        // 0.2 ms apart, from 1 ms after the accepted frame.
        for k in 0..11u64 {
            let t = T + MS + k * 200_000;
            let mut c = f.nominal(t);
            c.frame.crc_ok = Some(false);
            let v = f.fw.check_joint(&c, t);
            assert_eq!(reason(&v), RejectReason::CrcInvalid);
            rejected += 1;
            if v.output().is_some() {
                emitted += 1;
            }
        }
        // Emissions at +1.0, +2.0 and +3.0 ms only.
        assert_eq!((rejected, emitted), (11, 3), "{platform:?}");
    }
}

#[test]
fn f4_joint_channels_require_a_rate_with_a_minimum_interval() {
    let mut s = joint_spec(12, 12);
    s.rate = None;
    let e = compile(qp(), s).unwrap_err();
    assert!(matches!(e, ConfigError::InvalidRate { .. }), "{e:?}");
    let mut s = joint_spec(12, 12);
    s.rate = Some(JointRate {
        expected_hz: 500.0,
        min_interval_ns: 0,
        max_interval_ns: 10 * MS,
    });
    let e = compile(qp(), s).unwrap_err();
    assert!(matches!(e, ConfigError::InvalidRate { .. }), "{e:?}");
}

// ------------------------------------------------------------------ F5

#[test]
fn f5_humanoid_hold_escalates_once_per_episode_and_drops_feed_forward() {
    // max_hold_ns = 50 ms.
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    let first = f.nominal(T);
    assert!(f.fw.check_joint(&first, T).is_passed());
    let bad = |f: &JFx, t: u64| {
        let mut c = f.nominal(t);
        c.frame.crc_ok = Some(false);
        c
    };
    let v = f.fw.check_joint(&bad(&f, T + 10 * MS), T + 10 * MS);
    let held = v.output().unwrap().frame;
    assert_eq!(held.motor(0).unwrap().tau, good().tau);
    let s = f.fw.stats();
    assert_eq!((s.joint_hold_episodes, s.joint_holds_exceeded), (1, 0));
    assert_eq!(s.joint_hold_age_ns, 10 * MS);
    let _ = events(&mut f.fw);

    // Past max_hold_ns: still held (never limp), feed-forward torque zeroed,
    // gains and position targets kept; one Critical escalation event.
    for k in 0..3u64 {
        let t = T + 60 * MS + k * 10 * MS;
        let v = f.fw.check_joint(&bad(&f, t), t);
        assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
        let out = v.output().unwrap().frame;
        for (o, a) in out.motors().iter().zip(first.frame.motors()) {
            assert_eq!(o.tau, 0.0);
            assert_eq!((o.q, o.kp, o.kd, o.dq), (a.q, a.kp, a.kd, 0.0));
        }
    }
    let ev: Vec<_> = events(&mut f.fw)
        .into_iter()
        .filter(|e| e.rule == rules::JOINT_HOLD_EXCEEDED)
        .collect();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].count, 1, "once per hold episode");
    assert_eq!(ev[0].severity, Severity::Critical);
    assert_eq!(
        (ev[0].value, ev[0].limit),
        ((60 * MS) as f64, (50 * MS) as f64)
    );
    let s = f.fw.stats();
    assert_eq!((s.joint_hold_episodes, s.joint_holds_exceeded), (1, 1));
    assert_eq!(s.joint_hold_age_ns, 80 * MS);

    // A new accepted frame ends the episode; the next hold is a new one.
    let t = T + 100 * MS;
    assert!(f.fw.check_joint(&f.nominal(t), t).is_passed());
    assert_eq!(f.fw.stats().joint_hold_age_ns, 0);
    f.fw.check_joint(&bad(&f, t + MS), t + MS);
    f.fw.check_joint(&bad(&f, t + 70 * MS), t + 70 * MS);
    let s = f.fw.stats();
    assert_eq!((s.joint_hold_episodes, s.joint_holds_exceeded), (2, 2));
}

// ------------------------------------------------------------------ F6

#[test]
fn f6_humanoid_refuses_fail_open() {
    let e = compile(
        PlatformConfig {
            fault_policy: FaultPolicy::FailOpen,
            ..humanoid()
        },
        joint_spec(12, 12),
    )
    .unwrap_err();
    assert!(matches!(e, ConfigError::UnsafeSubstitute { .. }), "{e:?}");
    assert!(e.to_string().contains("fail_open"), "{e}");
    // Quadruped: still the OEM's choice.
    assert!(compile(
        PlatformConfig {
            fault_policy: FaultPolicy::FailOpen,
            ..qp()
        },
        joint_spec(12, 12),
    )
    .is_ok());
}

// ------------------------------------------------------------------ F8

#[test]
fn f8_mode_pr_and_mode_machine_must_match_their_pins() {
    let mut f = build_joint(humanoid(), true, 12, 12, |s| {
        s.pinned_mode_pr = Some(0);
        s.pinned_mode_machine = Some(5);
    });
    let with = |f: &JFx, t: u64, pr: Option<u8>, mm: Option<u8>| {
        let mut c = f.nominal(t);
        c.frame.mode_pr = pr;
        c.frame.mode_machine = mm;
        c
    };
    assert!(f
        .fw
        .check_joint(&with(&f, T, Some(0), Some(5)), T)
        .is_passed());
    let mut t = T;
    for (pr, mm) in [
        (Some(1), Some(5)),
        (Some(0), Some(6)),
        (None, Some(5)),
        (Some(0), None),
    ] {
        t += MS;
        let v = f.fw.check_joint(&with(&f, t, pr, mm), t);
        assert_eq!(
            reason(&v),
            RejectReason::JointModePinMismatch,
            "{pr:?} {mm:?}"
        );
        // The hold carries the pinned modes.
        let out = v.output().unwrap().frame;
        assert_eq!((out.mode_pr, out.mode_machine), (Some(0), Some(5)));
    }
    let ev = events(&mut f.fw);
    assert!(ev.iter().any(|e| e.rule == rules::JOINT_MODE_PIN_MISMATCH));
    // A damping substitute (quadruped) carries the pins too.
    let mut q = build_joint(qp(), true, 12, 12, |s| s.pinned_mode_pr = Some(1));
    let v = q.fw.check_joint(&with(&q, T, Some(0), None), T);
    assert_eq!(reason(&v), RejectReason::JointModePinMismatch);
    assert_eq!(v.output().unwrap().frame.mode_pr, Some(1));
    // Unpinned channel: anything goes (the gateway's business).
    let mut u = build_joint(humanoid(), true, 12, 12, |_| {});
    assert!(u.fw.check_joint(&with(&u, T, Some(7), None), T).is_passed());
}

// ------------------------------------------------------------------ F9

#[test]
fn f9_future_stamped_frame_does_not_block_on_time_frames() {
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    // Accepted, stamped 1.5 ms ahead (max_future_ns = 2 ms).
    assert!(f.fw.check_joint(&f.nominal(T + 1_500_000), T).is_passed());
    // On-time frame 1 ms later, stamped before the future one: accepted.
    let v = f.fw.check_joint(&f.nominal(T + 500_000), T + MS);
    assert!(v.is_passed(), "{v:?}");
    // The watermark still blocks a true replay of an older stamp.
    let v = f.fw.check_joint(&f.nominal(T + 500_000), T + 2 * MS);
    assert_eq!(reason(&v), RejectReason::OutOfOrder);
}

// ------------------------------------------------------------------ F10

#[test]
fn f10_timing_windows_are_bounded() {
    for (field, set) in [
        (
            "max_age_ns",
            (|s: &mut JointChannelSpec, v| s.max_age_ns = v) as fn(&mut JointChannelSpec, u64),
        ),
        ("max_future_ns", |s, v| s.max_future_ns = v),
    ] {
        let mut s = joint_spec(12, 12);
        set(&mut s, 10_000_000_000);
        assert!(compile(qp(), s).is_ok(), "{field} at 10 s");
        let mut s = joint_spec(12, 12);
        set(&mut s, 10_000_000_001);
        let e = compile(qp(), s).unwrap_err();
        assert!(
            matches!(e, ConfigError::InvalidLimit { field: f, .. } if f == field),
            "{e:?}"
        );
    }
}

#[test]
fn f10_below_minimum_gain_events_keep_the_smallest_gain() {
    let mut f = build_joint(humanoid(), true, 12, 12, |s| {
        for m in &mut s.motors {
            m.kp_min = 20.0;
        }
    });
    let mut t = T;
    for (slot, kp) in [(2usize, 15.0), (4, 5.0), (1, 10.0)] {
        t += MS;
        let c = f.with_slot(t, slot, MotorCmd::enabled(0.0, 0.0, 0.0, kp, 1.0));
        assert_eq!(
            reason(&f.fw.check_joint(&c, t)),
            RejectReason::JointGainBelowMinimum
        );
    }
    let ev = events(&mut f.fw);
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0].rule, rules::JOINT_GAIN_BELOW_MINIMUM);
    assert_eq!(ev[0].count, 3);
    assert_eq!((ev[0].value, ev[0].limit, ev[0].slot), (5.0, 20.0, Some(4)));
}
