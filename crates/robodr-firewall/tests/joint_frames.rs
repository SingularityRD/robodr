//! Low-level joint frames (`Firewall::check_joint`): decision table rows,
//! clamping, the humanoid no-zero rule, quadruped substitutes, CRC, rate and
//! staleness, configuration validation, the shipped Unitree example configs
//! and backward compatibility of the existing API.

mod common;
use common::*;
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_firewall::*;
use std::collections::BTreeMap;

fn reason(v: &JointVerdict) -> RejectReason {
    v.reject_reason()
        .unwrap_or_else(|| panic!("not rejected: {v:?}"))
}

fn rules_of(fw: &mut Firewall) -> Vec<(&'static str, Severity, EventAction, Option<u8>)> {
    let mut out = Vec::new();
    fw.drain_events(|e| out.push((e.rule, e.severity, e.action, e.slot)));
    out
}

const T: u64 = T0;

// ------------------------------------------------------------------ pass

#[test]
fn nominal_frames_pass_bit_exact_for_every_unitree_layout() {
    // (slots, actuated): G1 / H1-2 (35, 29), Go2 / B2 / H1 (20, 12 or 20),
    // Go1 / A1 (12, 12).
    for (slots, active) in [(35, 29), (35, 35), (20, 12), (20, 20), (12, 12)] {
        let mut f = build_joint(humanoid(), true, slots, active, |_| {});
        let c = f.nominal(T);
        let v = f.fw.check_joint(&c, T);
        assert_eq!(
            v,
            JointVerdict::Passed {
                cmd: c,
                would_have: None
            },
            "{slots}/{active}"
        );
        assert!(f.fw.events().is_empty());
    }
}

#[test]
fn idle_slots_parked_like_the_unitree_sdk_pass() {
    // Enabled, zero gains, PosStopF / VelStopF targets: inert, so neither
    // the position nor the velocity target is checked.
    let mut f = build_joint(humanoid(), true, 20, 12, |_| {});
    let parked = MotorCmd::enabled(2.146e9, 16000.0, 0.0, 0.0, 0.0);
    let c = JointCommand::new(f.ctl, f.low, T, jframe(20, 20, |_| parked));
    // Slots 0..12 are enabled in the envelope; all-zero gains are allowed
    // (kp_min = kd_min = 0); slots 12..20 are unused but not energised.
    assert!(f.fw.check_joint(&c, T).is_passed());
    // kp = 0 but kd > 0 on an enabled slot: q is still not checked, dq is.
    let damp = MotorCmd::enabled(2.146e9, 0.5, 0.0, 0.0, 2.0);
    let c = f.with_slot(T + 1, 0, damp);
    assert!(f.fw.check_joint(&c, T + 1).is_passed());
}

// ------------------------------------------------------------------ limit

#[test]
fn each_field_is_clamped_and_reported_with_its_slot() {
    let mut f = build_joint(humanoid(), true, 35, 29, |_| {});
    let cases: [(MotorCmd, JointLimitReasons, &str, MotorCmd); 6] = [
        (
            MotorCmd::enabled(1.5, 1.0, 2.0, 50.0, 1.0),
            JointLimitReasons::POSITION,
            rules::JOINT_POSITION_OUT_OF_ENVELOPE,
            MotorCmd::enabled(Q_LIM, 1.0, 2.0, 50.0, 1.0),
        ),
        (
            MotorCmd::enabled(-1.5, 1.0, 2.0, 50.0, 1.0),
            JointLimitReasons::POSITION,
            rules::JOINT_POSITION_OUT_OF_ENVELOPE,
            MotorCmd::enabled(-Q_LIM, 1.0, 2.0, 50.0, 1.0),
        ),
        (
            MotorCmd::enabled(0.2, -15.0, 2.0, 50.0, 1.0),
            JointLimitReasons::VELOCITY,
            rules::JOINT_VELOCITY_OUT_OF_ENVELOPE,
            MotorCmd::enabled(0.2, -DQ_MAX, 2.0, 50.0, 1.0),
        ),
        (
            MotorCmd::enabled(0.2, 1.0, -30.0, 50.0, 1.0),
            JointLimitReasons::TORQUE,
            rules::JOINT_TORQUE_OUT_OF_ENVELOPE,
            MotorCmd::enabled(0.2, 1.0, -TAU_MAX, 50.0, 1.0),
        ),
        (
            MotorCmd::enabled(0.2, 1.0, 2.0, 150.0, 1.0),
            JointLimitReasons::GAIN,
            rules::JOINT_GAIN_OUT_OF_ENVELOPE,
            MotorCmd::enabled(0.2, 1.0, 2.0, KP_MAX, 1.0),
        ),
        (
            MotorCmd::enabled(0.2, 1.0, 2.0, 50.0, 7.0),
            JointLimitReasons::GAIN,
            rules::JOINT_GAIN_OUT_OF_ENVELOPE,
            MotorCmd::enabled(0.2, 1.0, 2.0, 50.0, KD_MAX),
        ),
    ];
    for (i, (input, bit, rule, expect)) in cases.into_iter().enumerate() {
        let t = T + i as u64;
        let slot = 7 + i;
        let c = f.with_slot(t, slot, input);
        let v = f.fw.check_joint(&c, t);
        let JointVerdict::Limited { cmd, reasons } = v else {
            panic!("case {i}: {v:?}");
        };
        assert_eq!(reasons, bit, "case {i}");
        assert_eq!(cmd.frame.motor(slot), Some(&expect), "case {i}");
        // Everything else untouched, metadata kept.
        let mut want = c;
        *want.frame.motor_mut(slot).unwrap() = expect;
        assert_eq!(cmd, want);
        let ev = rules_of(&mut f.fw);
        assert_eq!(
            ev,
            vec![(rule, Severity::High, EventAction::Limited, Some(slot as u8))],
            "case {i}"
        );
    }
}

#[test]
fn several_clamps_in_one_frame_set_every_bit_and_keep_the_worst_slot() {
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    let mut c = f.nominal(T);
    *c.frame.motor_mut(1).unwrap() = MotorCmd::enabled(1.2, 12.0, 25.0, 120.0, 6.0);
    *c.frame.motor_mut(4).unwrap() = MotorCmd::enabled(1.8, 1.0, 2.0, 50.0, 1.0);
    let v = f.fw.check_joint(&c, T);
    let JointVerdict::Limited { reasons, cmd } = v else {
        panic!("{v:?}")
    };
    for b in [
        JointLimitReasons::POSITION,
        JointLimitReasons::VELOCITY,
        JointLimitReasons::TORQUE,
        JointLimitReasons::GAIN,
    ] {
        assert!(reasons.contains(b));
    }
    assert_eq!(
        cmd.frame.motor(1),
        Some(&MotorCmd::enabled(Q_LIM, DQ_MAX, TAU_MAX, KP_MAX, KD_MAX))
    );
    let ev = rules_of(&mut f.fw);
    assert_eq!(ev.len(), 4);
    let pos = ev
        .iter()
        .find(|e| e.0 == rules::JOINT_POSITION_OUT_OF_ENVELOPE)
        .unwrap();
    // Slot 4 is further outside (0.8 rad) than slot 1 (0.2 rad).
    assert_eq!(pos.3, Some(4));
}

#[test]
fn envelope_max_joint_speed_tightens_dq_max() {
    let mut f = build_joint(humanoid(), true, 12, 12, |s| {
        for m in &mut s.motors {
            m.dq_max = Some(100.0);
        }
    });
    let c = f.with_slot(T, 0, MotorCmd::enabled(0.0, 45.0, 0.0, 10.0, 1.0));
    let v = f.fw.check_joint(&c, T);
    assert_eq!(jout(&v).motor(0).unwrap().dq, ENV_DQ);
    assert!(v.is_limited());
}

// ------------------------------------------------------------------ reject

#[test]
fn far_outside_values_are_rejected_not_clamped() {
    let f2 = 2.0; // default hard_reject_factor
    let cases = [
        (
            MotorCmd::enabled(1.0 + 2.0 * Q_LIM + 0.01, 0.0, 0.0, 10.0, 0.0),
            RejectReason::JointPositionOutOfEnvelope,
        ),
        (
            MotorCmd::enabled(0.0, f2 * DQ_MAX + 0.1, 0.0, 10.0, 1.0),
            RejectReason::JointVelocityOutOfEnvelope,
        ),
        (
            MotorCmd::enabled(0.0, 0.0, -(f2 * TAU_MAX + 0.1), 10.0, 1.0),
            RejectReason::JointTorqueOutOfEnvelope,
        ),
        (
            MotorCmd::enabled(0.0, 0.0, 0.0, f2 * KP_MAX + 1.0, 1.0),
            RejectReason::JointGainOutOfEnvelope,
        ),
        (
            MotorCmd::enabled(0.0, 0.0, 0.0, 10.0, f2 * KD_MAX + 0.1),
            RejectReason::JointGainOutOfEnvelope,
        ),
    ];
    for (i, (m, why)) in cases.into_iter().enumerate() {
        let mut f = build_joint(humanoid(), true, 35, 29, |_| {});
        assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
        let c = f.with_slot(T + 1, 3, m);
        let v = f.fw.check_joint(&c, T + 1);
        assert_eq!(reason(&v), why, "case {i}");
        let ev = rules_of(&mut f.fw);
        let (rule, sev) = reject_rule(why);
        assert_eq!(
            ev,
            vec![(
                rule,
                sev,
                EventAction::Rejected(Some(SubstituteKind::HoldLast)),
                Some(3)
            )],
            "case {i}"
        );
        assert_eq!(sev, Severity::Critical);
    }
    // Exactly at the hard bound is still a clamp.
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    let c = f.with_slot(T, 0, MotorCmd::enabled(0.0, 0.0, f2 * TAU_MAX, 10.0, 0.0));
    assert!(f.fw.check_joint(&c, T).is_limited());
}

#[test]
fn gains_below_minimum_are_rejected_never_raised() {
    let mut f = build_joint(humanoid(), true, 12, 12, |s| {
        for m in &mut s.motors {
            m.kp_min = 20.0;
            m.kd_min = 0.5;
        }
    });
    // kp below min.
    let c = f.with_slot(T, 2, MotorCmd::enabled(0.0, 0.0, 0.0, 5.0, 1.0));
    assert_eq!(
        reason(&f.fw.check_joint(&c, T)),
        RejectReason::JointGainOutOfEnvelope
    );
    // A limp frame: every motor switched off (effective gains zero).
    let limp = JointCommand::new(f.ctl, f.low, T + 1, jframe(12, 12, |_| MotorCmd::OFF));
    assert_eq!(
        reason(&f.fw.check_joint(&limp, T + 1)),
        RejectReason::JointGainOutOfEnvelope
    );
    // Zero-gain "damping" frame (kp = 0): rejected too.
    let damp = JointCommand::new(
        f.ctl,
        f.low,
        T + 2,
        jframe(12, 12, |_| MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, 2.0)),
    );
    assert_eq!(
        reason(&f.fw.check_joint(&damp, T + 2)),
        RejectReason::JointGainOutOfEnvelope
    );
    // With minimums of zero a disabled motor on an enabled slot is allowed.
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    let c = f.with_slot(T, 2, MotorCmd::OFF);
    assert!(f.fw.check_joint(&c, T).is_passed());
}

#[test]
fn energising_an_unused_slot_is_rejected() {
    let mut f = build_joint(humanoid(), true, 20, 12, |_| {});
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    for (i, m) in [
        MotorCmd::enabled(0.0, 0.0, 0.0, 1.0, 0.0),
        MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, 0.1),
        MotorCmd::enabled(0.0, 0.0, 0.5, 0.0, 0.0),
    ]
    .into_iter()
    .enumerate()
    {
        let t = T + 1 + i as u64;
        let c = f.with_slot(t, 15, m);
        let v = f.fw.check_joint(&c, t);
        assert_eq!(reason(&v), RejectReason::DisabledMotorEnergised);
        assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    }
    let ev = rules_of(&mut f.fw);
    assert_eq!(ev.len(), 1, "coalesced: {ev:?}");
    assert_eq!(ev[0].0, rules::DISABLED_MOTOR_ENERGISED);
    assert_eq!(ev[0].1, Severity::Critical);
    assert_eq!(ev[0].3, Some(15));
    // Not energised: gains set but the motor is off.
    let c = f.with_slot(
        T + 10,
        15,
        MotorCmd {
            kp: 80.0,
            ..MotorCmd::OFF
        },
    );
    assert!(f.fw.check_joint(&c, T + 10).is_passed());
}

#[test]
fn crc_is_required_by_default_and_invalid_is_always_rejected() {
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    for (t, crc) in [(T, None), (T + 1, Some(false))] {
        let mut c = f.nominal(t);
        c.frame.crc_ok = crc;
        let v = f.fw.check_joint(&c, t);
        assert_eq!(reason(&v), RejectReason::CrcInvalid, "{crc:?}");
        // Nothing accepted yet on a humanoid: emit nothing.
        assert_eq!(v.output(), None);
    }
    let ev = rules_of(&mut f.fw);
    assert!(ev
        .iter()
        .all(|e| e.0 == rules::CRC_INVALID && e.1 == Severity::High));

    let mut f = build_joint(humanoid(), true, 12, 12, |s| s.require_crc = false);
    let mut c = f.nominal(T);
    c.frame.crc_ok = None;
    assert!(f.fw.check_joint(&c, T).is_passed());
    let mut c = f.nominal(T + 1);
    c.frame.crc_ok = Some(false);
    assert_eq!(
        reason(&f.fw.check_joint(&c, T + 1)),
        RejectReason::CrcInvalid
    );
}

#[test]
fn shape_values_and_time() {
    let mut f = build_joint(humanoid(), true, 20, 12, |_| {});
    // Wrong slot count.
    let c = JointCommand::new(f.ctl, f.low, T, jframe(12, 12, |_| good()));
    assert_eq!(reason(&f.fw.check_joint(&c, T)), RejectReason::KindMismatch);
    // NaN anywhere, including an unused slot.
    for slot in [0, 19] {
        let c = f.with_slot(
            T + 1,
            slot,
            MotorCmd {
                q: f64::NAN,
                ..MotorCmd::OFF
            },
        );
        assert_eq!(
            reason(&f.fw.check_joint(&c, T + 1)),
            RejectReason::NonFinite
        );
    }
    // Staleness deadline (default 20 ms), future bound (default 2 ms).
    let now = T + 100 * MS;
    assert!(f.fw.check_joint(&f.nominal(now - 20 * MS), now).is_passed());
    assert_eq!(
        reason(
            &f.fw
                .check_joint(&f.nominal(now + MS - 20 * MS - 1), now + MS)
        ),
        RejectReason::Stale
    );
    assert_eq!(
        reason(&f.fw.check_joint(&f.nominal(now + 5 * MS), now + 2 * MS)),
        RejectReason::FutureTimestamp
    );
    // Replay of a fresh, accepted frame.
    assert!(f
        .fw
        .check_joint(&f.nominal(now + 3 * MS), now + 3 * MS)
        .is_passed());
    assert_eq!(
        reason(&f.fw.check_joint(&f.nominal(now + 3 * MS), now + 4 * MS)),
        RejectReason::OutOfOrder
    );
}

#[test]
fn rate_window_too_early_emits_nothing_and_late_is_recorded() {
    let mut f = build_joint(humanoid(), true, 12, 12, |s| {
        s.rate = Some(JointRate {
            expected_hz: 1000.0,
            min_interval_ns: 500_000,
            max_interval_ns: 3 * MS,
        });
    });
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    // 0.4 ms later: too early, nothing substituted, state untouched.
    let t = T + 400_000;
    let v = f.fw.check_joint(&f.nominal(t), t);
    assert_eq!(
        v,
        JointVerdict::Rejected {
            reason: RejectReason::RateLimited,
            substitute: None
        }
    );
    // The early frame's stamp was not stored: an earlier-stamped frame at
    // the right time is not "out of order" against it.
    let t = T + 500_000;
    assert!(f.fw.check_joint(&f.nominal(t - 1), t).is_passed());
    let _ = rules_of(&mut f.fw);
    // 5 ms gap: the late frame passes, the gap is recorded.
    let t = t + 5 * MS;
    assert!(f.fw.check_joint(&f.nominal(t), t).is_passed());
    let ev = rules_of(&mut f.fw);
    assert_eq!(
        ev,
        vec![(
            rules::JOINT_RATE_VIOLATION,
            Severity::Medium,
            EventAction::ObservedOnly,
            None
        )]
    );
    let d = {
        let mut f2 = build_joint(humanoid(), true, 12, 12, |s| {
            s.rate = Some(JointRate::around(500.0));
        });
        f2.fw.check_joint(&f2.nominal(T), T);
        f2.fw.check_joint(&f2.nominal(T + 10 * MS), T + 10 * MS);
        f2.fw.drain_deviations()
    };
    assert_eq!(d.len(), 1);
    assert!(d[0].detail.contains("recorded only"), "{}", d[0].detail);
}

#[test]
fn channels_and_sources() {
    let mut f = build_joint(
        PlatformConfig {
            foreign_source_action: ForeignSourceAction::Substitute,
            foreign_substitute_min_interval_ns: 0,
            ..humanoid()
        },
        true,
        12,
        12,
        |_| {},
    );
    // Joint channel ids come after the twist channel's.
    assert_eq!(f.base, ChannelId(0));
    assert_eq!(f.low, ChannelId(1));
    assert!(f.fw.policy().is_joint_channel(f.low));
    assert!(!f.fw.policy().is_joint_channel(f.base));
    assert_eq!(f.fw.policy().channel_name(f.low), Some("/lowcmd"));
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());

    // Unknown channel: nothing.
    let mut c = f.nominal(T + 1);
    c.channel = ChannelId(7);
    assert_eq!(
        f.fw.check_joint(&c, T + 1),
        JointVerdict::Rejected {
            reason: RejectReason::UnknownChannel,
            substitute: None
        }
    );
    // A joint frame on the twist channel (allowed source there): kind.
    let c = JointCommand::new(f.nav, f.base, T + 1, jframe(12, 12, |_| good()));
    assert_eq!(
        f.fw.check_joint(&c, T + 1),
        JointVerdict::Rejected {
            reason: RejectReason::KindMismatch,
            substitute: None
        }
    );
    // A twist on the joint channel through `check`: kind, nothing emitted.
    let v = f.fw.check(&twist_cmd(f.ctl, f.low, T + 1, vx(0.1)), T + 1);
    assert_eq!(
        v,
        Verdict::Rejected {
            reason: RejectReason::KindMismatch,
            substitute: None
        }
    );
    // ... and a foreign source on it through `check` is still a source
    // rejection.
    let v = f.fw.check(&twist_cmd(f.nav, f.low, T + 1, vx(0.1)), T + 1);
    assert_eq!(v.reject_reason(), Some(RejectReason::UnauthorizedSource));
    // Foreign sources on the joint channel, opt-in substitute: a hold.
    let mut c = f.nominal(T + 2);
    c.source = f.nav;
    let v = f.fw.check_joint(&c, T + 2);
    assert_eq!(v.reject_reason(), Some(RejectReason::UnauthorizedSource));
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    c.source = SourceId::UNKNOWN;
    let v = f.fw.check_joint(&c, T + 3);
    assert_eq!(v.reject_reason(), Some(RejectReason::UnknownSource));
    let ev = rules_of(&mut f.fw);
    assert!(ev
        .iter()
        .any(|e| e.0 == rules::REJECTED_UNAUTHORIZED_SOURCE && e.1 == Severity::Critical));

    // Default (Drop): nothing.
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    let mut c = f.nominal(T + 1);
    c.source = SourceId::UNKNOWN;
    assert_eq!(f.fw.check_joint(&c, T + 1).output(), None);
}

// ------------------------------------------------------------ humanoid rule

/// Every rejection reason the joint path can produce, after one accepted
/// frame, on a humanoid: the substitute is always the held frame.
#[test]
fn humanoid_never_substitutes_zero_or_damping() {
    let mut f = build_joint(humanoid(), true, 35, 29, |s| {
        s.rate = Some(JointRate {
            expected_hz: 500.0,
            min_interval_ns: 0,
            max_interval_ns: 4 * MS,
        });
        for m in &mut s.motors {
            if m.enabled {
                m.kp_min = 10.0;
            }
        }
    });
    let first = f.nominal(T);
    assert!(f.fw.check_joint(&first, T).is_passed());
    let mut held = first.frame;
    for i in 0..35 {
        if let Some(m) = held.motor_mut(i) {
            m.dq = 0.0;
        }
    }
    held.crc_ok = Some(true);

    let mut t = T;
    let mut next = |dt: u64| {
        t += dt;
        t
    };
    let mut bad: Vec<(JointCommand, u64)> = Vec::new();
    let n = next(MS);
    let mut c = f.nominal(n);
    c.frame.crc_ok = Some(false);
    bad.push((c, n));
    let n = next(MS);
    bad.push((f.with_slot(n, 0, MotorCmd::OFF), n)); // limp (kp_min)
    let n = next(MS);
    bad.push((
        f.with_slot(n, 30, MotorCmd::enabled(0.0, 0.0, 1.0, 0.0, 0.0)),
        n,
    ));
    let n = next(MS);
    bad.push((
        f.with_slot(n, 1, MotorCmd::enabled(9.0, 0.0, 0.0, 50.0, 0.0)),
        n,
    ));
    let n = next(MS);
    bad.push((
        f.with_slot(n, 1, MotorCmd::enabled(0.0, 0.0, 1e6, 50.0, 0.0)),
        n,
    ));
    let n = next(MS);
    bad.push((
        f.with_slot(
            n,
            1,
            MotorCmd {
                tau: f64::INFINITY,
                ..good()
            },
        ),
        n,
    ));
    let n = next(MS);
    bad.push((f.nominal(n - 30 * MS), n)); // stale
    let n = next(MS);
    bad.push((f.nominal(n + 30 * MS), n)); // future
    let n = next(MS);
    bad.push((
        JointCommand::new(f.ctl, f.low, n, jframe(20, 12, |_| good())),
        n,
    ));
    for (c, now) in bad {
        let v = f.fw.check_joint(&c, now);
        assert!(v.is_rejected(), "{v:?}");
        let JointVerdict::Rejected {
            substitute: Some(s),
            ..
        } = v
        else {
            panic!("humanoid must hold: {v:?}")
        };
        assert_eq!(s.kind, SubstituteKind::HoldLast, "{v:?}");
        assert_eq!(s.cmd.frame, held);
        assert_eq!(s.cmd.source, SourceId::FIREWALL);
        assert_eq!(s.cmd.stamp_ns, now);
    }
    // Clock regression: still a hold, never damping.
    let v = f.fw.check_joint(&f.nominal(T), T);
    assert_eq!(v.reject_reason(), Some(RejectReason::ClockRegression));
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    // No hold timeout: ten seconds later the frame is still held.
    let late = t + 10_000 * MS;
    let mut c = f.nominal(late);
    c.frame.crc_ok = None;
    let v = f.fw.check_joint(&c, late);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    // A gateway-declared fault holds too (FailHold).
    let v = f.fw.joint_fault_verdict(&f.nominal(late + 1), late + 1);
    assert_eq!(v.reject_reason(), Some(RejectReason::InternalFault));
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    // Deviation text names the action.
    let d = f.fw.drain_deviations();
    assert!(d
        .iter()
        .all(|d| !d.detail.contains("damping") && !d.detail.contains("zero velocity")));
    assert!(d.iter().any(|d| d.detail.contains("last valid frame held")));
    assert!(d.iter().any(|d| d.detail.contains("motor slot 30")));
}

#[test]
fn humanoid_with_nothing_to_hold_emits_nothing() {
    let mut f = build_joint(humanoid(), true, 35, 29, |_| {});
    let mut c = f.nominal(T);
    c.frame.crc_ok = Some(false);
    let v = f.fw.check_joint(&c, T);
    assert_eq!(
        v,
        JointVerdict::Rejected {
            reason: RejectReason::CrcInvalid,
            substitute: None
        }
    );
    let v = f.fw.joint_fault_verdict(&f.nominal(T + 1), T + 1);
    assert_eq!(v.output(), None);
}

#[test]
fn humanoid_config_refuses_zero_and_fail_safe() {
    let compile = |pf: PlatformConfig| {
        Policy::compile_with_joints(
            &joint_profile(true),
            pf,
            &twist_specs(),
            &joint_specs(joint_spec(35, 29)),
        )
    };
    let e = compile(PlatformConfig {
        fail_behaviour: FailBehaviour::ZeroVelocity,
        ..humanoid()
    })
    .unwrap_err();
    assert!(matches!(e, ConfigError::UnsafeSubstitute { .. }), "{e:?}");
    assert!(e.to_string().contains("fall"), "{e}");
    assert!(e.to_string().contains("zero_velocity"), "{e}");
    let e = compile(PlatformConfig {
        fault_policy: FaultPolicy::FailSafe,
        ..humanoid()
    })
    .unwrap_err();
    assert!(matches!(e, ConfigError::UnsafeSubstitute { .. }), "{e:?}");
    assert!(e.to_string().contains("fail_safe"), "{e}");
    // The defaults are refused for a humanoid with a joint channel ...
    assert!(compile(PlatformConfig {
        morphology: Morphology::Humanoid,
        ..Default::default()
    })
    .is_err());
    // ... but fine without one (a humanoid's twist channel is a request to
    // its own balance controller).
    let mut p = joint_profile(true);
    p.motion_envelopes.remove("/lowcmd");
    assert!(Policy::compile(
        &p,
        PlatformConfig {
            morphology: Morphology::Humanoid,
            ..Default::default()
        },
        &twist_specs()
    )
    .is_ok());
    // FailOpen and pass-through (never substitutes) are allowed.
    assert!(compile(PlatformConfig {
        fault_policy: FaultPolicy::FailOpen,
        ..humanoid()
    })
    .is_ok());
    assert!(compile(PlatformConfig {
        fail_behaviour: FailBehaviour::PassThroughObserveOnly,
        fault_policy: FaultPolicy::FailSafe,
        ..humanoid()
    })
    .is_ok());
    // Quadrupeds keep every option.
    for fb in [
        FailBehaviour::ZeroVelocity,
        FailBehaviour::HoldLast { max_hold_ns: 1 },
        FailBehaviour::PassThroughObserveOnly,
    ] {
        for fp in [
            FaultPolicy::FailSafe,
            FaultPolicy::FailOpen,
            FaultPolicy::FailHold,
        ] {
            assert!(compile(PlatformConfig {
                fault_policy: fp,
                ..quadruped(fb)
            })
            .is_ok());
        }
    }
}

// ------------------------------------------------------------- quadruped

fn damping(slots: usize, active: usize, kd: f64) -> JointFrame {
    jframe(slots, active, |_| MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, kd))
}

#[test]
fn quadruped_zero_velocity_substitutes_the_damping_frame() {
    let mut f = build_joint(quadruped(FailBehaviour::ZeroVelocity), true, 20, 12, |s| {
        s.damping_kd = 2.0
    });
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    let mut c = f.nominal(T + 1);
    c.frame.crc_ok = Some(false);
    let v = f.fw.check_joint(&c, T + 1);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
    assert_eq!(jout(&v), damping(20, 12, 2.0));
    // damping_kd is capped at each slot's kd_max.
    let mut f = build_joint(quadruped(FailBehaviour::ZeroVelocity), true, 12, 12, |s| {
        s.damping_kd = 50.0
    });
    let v = f.fw.joint_fault_verdict(&f.nominal(T), T);
    assert_eq!(jout(&v), damping(12, 12, KD_MAX));
    let d = f.fw.drain_deviations();
    assert!(
        d[0].detail.contains("damping frame emitted"),
        "{}",
        d[0].detail
    );
}

#[test]
fn quadruped_hold_last_expires_into_damping() {
    let mut f = build_joint(
        quadruped(FailBehaviour::HoldLast {
            max_hold_ns: 50 * MS,
        }),
        true,
        20,
        12,
        |_| {},
    );
    let bad = |f: &JFx, t: u64| {
        let mut c = f.nominal(t);
        c.frame.crc_ok = None;
        c
    };
    // Nothing accepted yet: damping.
    let v = f.fw.check_joint(&bad(&f, T), T);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
    assert!(f.fw.check_joint(&f.nominal(T + 1), T + 1).is_passed());
    let v = f.fw.check_joint(&bad(&f, T + 2), T + 2);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    let mut want = f.nominal(T + 1).frame;
    for i in 0..12 {
        want.motor_mut(i).unwrap().dq = 0.0;
    }
    assert_eq!(jout(&v), want);
    // Held at exactly max_hold, damped after.
    let v = f.fw.check_joint(&bad(&f, T + 1 + 50 * MS), T + 1 + 50 * MS);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    let v = f.fw.check_joint(&bad(&f, T + 2 + 50 * MS), T + 2 + 50 * MS);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
    // Clock regression: never hold on a quadruped.
    assert!(f
        .fw
        .check_joint(&f.nominal(T + 60 * MS), T + 60 * MS)
        .is_passed());
    let v = f.fw.check_joint(&f.nominal(T + 61 * MS), T + 59 * MS);
    assert_eq!(v.reject_reason(), Some(RejectReason::ClockRegression));
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
}

#[test]
fn quadruped_fault_policies() {
    for (fp, want) in [
        (FaultPolicy::FailSafe, Some(SubstituteKind::Zero)),
        (FaultPolicy::FailHold, Some(SubstituteKind::HoldLast)),
    ] {
        let mut f = build_joint(
            PlatformConfig {
                fault_policy: fp,
                ..quadruped(FailBehaviour::ZeroVelocity)
            },
            true,
            12,
            12,
            |_| {},
        );
        assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
        let v = f.fw.joint_fault_verdict(&f.nominal(T + 1), T + 1);
        assert_eq!(v.substitute_kind(), want, "{fp:?}");
    }
    let mut f = build_joint(
        PlatformConfig {
            fault_policy: FaultPolicy::FailOpen,
            ..quadruped(FailBehaviour::ZeroVelocity)
        },
        true,
        12,
        12,
        |_| {},
    );
    let c = f.nominal(T);
    assert_eq!(
        f.fw.joint_fault_verdict(&c, T),
        JointVerdict::Passed {
            cmd: c,
            would_have: Some(JointWouldHave::Rejected {
                reason: RejectReason::InternalFault
            })
        }
    );
}

#[test]
fn quadruped_foreign_substitute_damps() {
    let mut f = build_joint(
        PlatformConfig {
            foreign_source_action: ForeignSourceAction::Substitute,
            ..quadruped(FailBehaviour::HoldLast {
                max_hold_ns: 500 * MS,
            })
        },
        true,
        12,
        12,
        |_| {},
    );
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    let mut c = f.nominal(T + 1);
    c.source = SourceId::UNKNOWN;
    let v = f.fw.check_joint(&c, T + 1);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
    // Bounded: a second one within the interval emits nothing.
    let v = f.fw.check_joint(&c, T + 2);
    assert_eq!(v.output(), None);
}

// ------------------------------------------------------------- observe

#[test]
fn observe_mode_forwards_bit_exact_with_would_have() {
    let mut f = build_joint(humanoid(), false, 12, 12, |_| {});
    assert!(!f.fw.is_enforcing());
    let c = f.with_slot(T, 0, MotorCmd::enabled(1.5, 0.0, 0.0, 10.0, 0.0));
    let v = f.fw.check_joint(&c, T);
    let JointVerdict::Passed {
        cmd,
        would_have: Some(JointWouldHave::Limited { reasons, .. }),
    } = v
    else {
        panic!("{v:?}")
    };
    assert_eq!(cmd, c);
    assert_eq!(reasons, JointLimitReasons::POSITION);
    let mut c = f.nominal(T + 1);
    c.frame.crc_ok = Some(false);
    let v = f.fw.check_joint(&c, T + 1);
    assert_eq!(
        v,
        JointVerdict::Passed {
            cmd: c,
            would_have: Some(JointWouldHave::Rejected {
                reason: RejectReason::CrcInvalid
            })
        }
    );
    let d = f.fw.drain_deviations();
    assert!(d.iter().all(|d| d.mode == robodr_events::Mode::Observe));
}

// ----------------------------------------------------------- configuration

fn compile_one(spec: JointChannelSpec) -> Result<Policy, ConfigError> {
    Policy::compile_with_joints(
        &joint_profile(true),
        humanoid(),
        &twist_specs(),
        &joint_specs(spec),
    )
}

#[test]
fn config_validation_fails_closed() {
    let err = |tweak: &dyn Fn(&mut JointChannelSpec)| {
        let mut s = joint_spec(20, 12);
        tweak(&mut s);
        compile_one(s).unwrap_err()
    };
    let motor = |e: ConfigError| match e {
        ConfigError::InvalidMotorLimit {
            slot, field, why, ..
        } => (slot, field, why),
        other => panic!("{other:?}"),
    };
    // Motor table size.
    assert!(matches!(
        err(&|s| s.motors.clear()),
        ConfigError::InvalidMotorCount { count: 0, .. }
    ));
    assert!(matches!(
        err(&|s| s.motors = vec![MotorLimits::disabled(); MAX_MOTORS + 1]),
        ConfigError::InvalidMotorCount { count: 36, .. }
    ));
    // Non-finite / negative / missing / inverted, with slot and field.
    assert_eq!(
        motor(err(&|s| s.motors[3].tau_max = Some(f64::NAN))).1,
        "tau_max"
    );
    assert_eq!(
        motor(err(&|s| s.motors[3].q_max = Some(f64::INFINITY))),
        (3, "q_max", "must be finite")
    );
    assert_eq!(
        motor(err(&|s| s.motors[4].dq_max = Some(-1.0))),
        (4, "dq_max", "must be >= 0")
    );
    assert_eq!(
        motor(err(&|s| s.motors[5].kp_max = None)),
        (5, "kp_max", "is required for an enabled slot")
    );
    assert_eq!(
        motor(err(&|s| {
            s.motors[6].q_min = Some(0.5);
            s.motors[6].q_max = Some(-0.5);
        })),
        (6, "q_min", "is greater than q_max")
    );
    assert_eq!(
        motor(err(&|s| s.motors[7].kp_min = 200.0)),
        (7, "kp_min", "is greater than kp_max")
    );
    assert_eq!(
        motor(err(&|s| s.motors[7].kd_min = -0.1)),
        (7, "kd_min", "must be >= 0")
    );
    // Malformed values on a disabled slot are still refused.
    assert_eq!(
        motor(err(&|s| s.motors[15].tau_max = Some(f64::NAN))),
        (15, "tau_max", "must be finite")
    );
    // Channel-level.
    assert!(matches!(
        err(&|s| s.hard_reject_factor = 0.9),
        ConfigError::InvalidLimit {
            field: "hard_reject_factor",
            ..
        }
    ));
    assert!(matches!(
        err(&|s| s.damping_kd = f64::NAN),
        ConfigError::InvalidLimit {
            field: "damping_kd",
            ..
        }
    ));
    assert!(matches!(
        err(&|s| s.max_age_ns = 0),
        ConfigError::InvalidTiming {
            field: "max_age_ns",
            ..
        }
    ));
    for bad in [
        JointRate {
            expected_hz: f64::NAN,
            min_interval_ns: 0,
            max_interval_ns: 1,
        },
        JointRate {
            expected_hz: 0.0,
            min_interval_ns: 0,
            max_interval_ns: 1,
        },
        JointRate {
            expected_hz: 1000.0,
            min_interval_ns: 0,
            max_interval_ns: 0,
        },
        JointRate {
            expected_hz: 1000.0,
            min_interval_ns: 2 * MS,
            max_interval_ns: 3 * MS,
        },
        JointRate {
            expected_hz: 1000.0,
            min_interval_ns: 0,
            max_interval_ns: MS / 2,
        },
        JointRate {
            expected_hz: 1000.0,
            min_interval_ns: 3 * MS,
            max_interval_ns: 2 * MS,
        },
    ] {
        let e = err(&|s| s.rate = Some(bad));
        assert!(
            matches!(e, ConfigError::InvalidRate { .. }),
            "{bad:?}: {e:?}"
        );
        assert!(!e.to_string().is_empty());
    }
    assert!(matches!(
        err(&|s| s.allowed_sources.clear()),
        ConfigError::NoAllowedSources(_)
    ));
    assert!(matches!(
        err(&|s| s.allowed_sources = vec!["bbbbbbbbbbbbbbbbbbbbbbbb".into()]),
        ConfigError::SourceNotInProfile { .. }
    ));
    // Every message is readable.
    let e = err(&|s| s.motors[3].tau_max = Some(f64::NAN));
    assert_eq!(
        e.to_string(),
        "joint channel /lowcmd: motor slot 3: tau_max must be finite"
    );

    // Channel-map consistency.
    let p = joint_profile(true);
    let mut both = twist_specs();
    both.insert("/lowcmd".into(), ChannelSpec::default());
    assert!(matches!(
        Policy::compile_with_joints(&p, humanoid(), &both, &joint_specs(joint_spec(12, 12))),
        Err(ConfigError::DuplicateChannel(_))
    ));
    assert!(matches!(
        Policy::compile_with_joints(&p, humanoid(), &twist_specs(), &BTreeMap::new()),
        Err(ConfigError::ChannelWithoutSpec(_))
    ));
    let mut extra = joint_specs(joint_spec(12, 12));
    extra.insert("/other".into(), joint_spec(12, 12));
    assert!(matches!(
        Policy::compile_with_joints(&p, humanoid(), &twist_specs(), &extra),
        Err(ConfigError::ChannelNotInProfile(_))
    ));
}

#[test]
fn json_config_round_trip_and_strictness() {
    let text = r#"{
        "platform": { "morphology": "quadruped", "fail_behaviour": "zero_velocity" },
        "channels": { "/cmd_vel": { "allowed_sources": ["0123456789abcdef0123456700000203"],
                                    "max_angular_speed": 2.0 } },
        "joint_channels": { "/lowcmd": {
            "allowed_sources": ["0123456789abcdef0123456700000103"],
            "rate": { "expected_hz": 1000.0, "min_interval_ns": 500000, "max_interval_ns": 3000000 },
            "motors": [
                { "enabled": true, "q_min": -1, "q_max": 1, "dq_max": 10, "tau_max": 20,
                  "kp_max": 100, "kd_max": 5 },
                { "name": "spare" }
            ] } }
    }"#;
    let cfg = FirewallConfig::from_json(text).unwrap();
    assert_eq!(cfg.platform.morphology, Morphology::Quadruped);
    assert_eq!(cfg.platform.event_capacity, 256);
    let js = &cfg.joint_channels["/lowcmd"];
    assert!(js.require_crc, "require_crc defaults to true");
    assert_eq!(js.motors.len(), 2);
    assert!(!js.motors[1].enabled);
    let pol = cfg.compile(&joint_profile(true)).unwrap();
    assert!(pol.is_joint_channel(pol.channel_id("/lowcmd").unwrap()));
    // Serialises back to an equal config.
    let back = serde_json::to_string(&cfg).unwrap();
    assert_eq!(FirewallConfig::from_json(&back).unwrap(), cfg);
    // Unknown fields anywhere are refused.
    for typo in [
        r#"{ "platfrom": {} }"#,
        r#"{ "platform": { "morphologie": "humanoid" } }"#,
        r#"{ "joint_channels": { "/lowcmd": { "motors": [ { "q_mx": 1 } ] } } }"#,
        r#"{ "joint_channels": { "/lowcmd": { "rate": { "expected_hz": 1, "min_interval_ns": 0, "max_interval_ns": 1, "x": 1 } } } }"#,
        r#"{ "platform": { "morphology": "centaur" } }"#,
        r#"{ "platform": { "fault_policy": "fail_maybe" } }"#,
    ] {
        let e = FirewallConfig::from_json(typo).unwrap_err();
        assert!(matches!(e, ConfigError::InvalidJson(_)), "{typo}");
        assert!(e.to_string().starts_with("invalid firewall JSON"));
    }
}

// ------------------------------------------------------- shipped examples

fn example(name: &str) -> FirewallConfig {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../config")
        .join(name);
    FirewallConfig::from_json(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn lowcmd_profile() -> Profile {
    let mut p = Profile {
        model: "unitree-example".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(PREFIX.into());
    p.writer_topics.insert("/lowcmd".into());
    p.motion_envelopes.insert(
        "/lowcmd".into(),
        robodr_events::profile::Envelope {
            max_joint_speed: Some(40.0),
            ..Default::default()
        },
    );
    p
}

/// A frame holding every enabled slot at the middle of its range with
/// moderate gains (inside every example envelope).
fn mid_frame(cfg: &FirewallConfig) -> JointFrame {
    let ms: Vec<MotorCmd> = cfg.joint_channels["/lowcmd"]
        .motors
        .iter()
        .map(|m| {
            if m.enabled {
                let q = (m.q_min.unwrap() + m.q_max.unwrap()) / 2.0;
                MotorCmd::enabled(q, 0.0, 0.0, m.kp_min.max(20.0), m.kd_min.max(1.0))
            } else {
                MotorCmd::OFF
            }
        })
        .collect();
    JointFrame::from_slice(&ms, Some(true)).unwrap()
}

#[test]
fn unitree_g1_example_compiles_and_holds() {
    let cfg = example("firewall.unitree-g1.example.json");
    assert_eq!(cfg.platform.morphology, Morphology::Humanoid);
    let motors = &cfg.joint_channels["/lowcmd"].motors;
    assert_eq!(motors.len(), 35);
    assert_eq!(motors.iter().filter(|m| m.enabled).count(), 29);
    let mut fw = Firewall::new(cfg.compile(&lowcmd_profile()).unwrap());
    let src = fw.source_id(&guid("00000103")).unwrap();
    let ch = fw.channel_id("/lowcmd").unwrap();
    let frame = mid_frame(&cfg);
    let c = JointCommand::new(src, ch, T, frame);
    assert!(fw.check_joint(&c, T).is_passed());
    // 2 ms later (500 Hz): an energised spare slot is refused and held.
    let mut bad = JointCommand::new(src, ch, T + 2 * MS, frame);
    *bad.frame.motor_mut(31).unwrap() = MotorCmd::enabled(0.0, 0.0, 5.0, 0.0, 0.0);
    let v = fw.check_joint(&bad, T + 2 * MS);
    assert_eq!(
        v.reject_reason(),
        Some(RejectReason::DisabledMotorEnergised)
    );
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    // A limp leg (kp below the example's kp_min) is refused and held.
    let mut limp = JointCommand::new(src, ch, T + 4 * MS, frame);
    *limp.frame.motor_mut(3).unwrap() = MotorCmd::OFF;
    let v = fw.check_joint(&limp, T + 4 * MS);
    assert_eq!(
        v.reject_reason(),
        Some(RejectReason::JointGainOutOfEnvelope)
    );
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    // The shipped humanoid config cannot be switched to zero_velocity.
    let mut unsafe_cfg = cfg.clone();
    unsafe_cfg.platform.fail_behaviour = FailBehaviour::ZeroVelocity;
    assert!(matches!(
        unsafe_cfg.compile(&lowcmd_profile()),
        Err(ConfigError::UnsafeSubstitute { .. })
    ));
}

#[test]
fn unitree_go2_example_compiles_and_damps_after_hold() {
    let cfg = example("firewall.unitree-go2.example.json");
    assert_eq!(cfg.platform.morphology, Morphology::Quadruped);
    let motors = &cfg.joint_channels["/lowcmd"].motors;
    assert_eq!(motors.len(), 20);
    assert_eq!(motors.iter().filter(|m| m.enabled).count(), 12);
    let mut fw = Firewall::new(cfg.compile(&lowcmd_profile()).unwrap());
    let src = fw.source_id(&guid("00000103")).unwrap();
    let ch = fw.channel_id("/lowcmd").unwrap();
    let frame = mid_frame(&cfg);
    assert!(fw
        .check_joint(&JointCommand::new(src, ch, T, frame), T)
        .is_passed());
    let mut bad = JointCommand::new(src, ch, T + 2 * MS, frame);
    bad.frame.crc_ok = Some(false);
    let v = fw.check_joint(&bad, T + 2 * MS);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::HoldLast));
    // After the 100 ms hold: the damping frame with the example's kd.
    let t = T + 200 * MS;
    bad.stamp_ns = t;
    let v = fw.check_joint(&bad, t);
    assert_eq!(v.substitute_kind(), Some(SubstituteKind::Zero));
    let out = jout(&v);
    for (m, lim) in out.motors().iter().zip(motors) {
        if lim.enabled {
            assert_eq!(*m, MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, 3.0));
        } else {
            assert_eq!(*m, MotorCmd::OFF);
        }
    }
}

// ------------------------------------------------- backward compatibility

#[test]
fn existing_api_is_unchanged_without_joint_channels() {
    // `Policy::compile` == `compile_with_joints` with no joint channel.
    let pol = Policy::compile(&profile(true), PlatformConfig::default(), &{
        BTreeMap::from([
            ("/cmd_vel".to_string(), base_spec()),
            ("/arm/cmd".to_string(), arm_spec()),
        ])
    })
    .unwrap();
    let pol2 = Policy::compile_with_joints(
        &profile(true),
        PlatformConfig::default(),
        &BTreeMap::from([
            ("/cmd_vel".to_string(), base_spec()),
            ("/arm/cmd".to_string(), arm_spec()),
        ]),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(pol, pol2);
    // Ids as before (lexical order of the legacy channels).
    assert_eq!(pol.channel_id("/arm/cmd"), Some(ChannelId(0)));
    assert_eq!(pol.channel_id("/cmd_vel"), Some(ChannelId(1)));
    assert!(!pol.is_joint_channel(ChannelId(0)));
    assert_eq!(PlatformConfig::default().morphology, Morphology::Other);
    // A legacy platform JSON (no morphology) still parses, with defaults.
    let cfg = FirewallConfig::from_json(
        r#"{ "platform": { "fail_behaviour": { "hold_last": { "max_hold_ns": 5 } } },
             "channels": { "/cmd_vel": { "allowed_sources": ["0123456789abcdef0123456700000103"],
                                         "max_angular_speed": 2.0 },
                           "/arm/cmd": { "kind": { "joints": { "count": 6 } },
                                         "allowed_sources": ["0123456789abcdef0123456700000303"] } } }"#,
    )
    .unwrap();
    assert_eq!(cfg.platform.morphology, Morphology::Other);
    assert_eq!(
        cfg.platform.fail_behaviour,
        FailBehaviour::HoldLast { max_hold_ns: 5 }
    );
    let mut want_base = base_spec();
    want_base.allowed_sources = vec![guid("00000103")];
    assert_eq!(cfg.channels["/cmd_vel"], want_base);
    assert_eq!(cfg.channels["/arm/cmd"], arm_spec());
    // The legacy twist path is untouched by a joint channel next to it.
    let mut f = build_joint(humanoid(), true, 12, 12, |_| {});
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T, vx(0.5)), T);
    assert!(v.is_passed());
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T + 1, vx(5.0)), T + 1);
    assert_eq!(v.reject_reason(), Some(RejectReason::OverHardLimit));
    // A humanoid's twist channel keeps the legacy substitute rules
    // (HoldLast here: the accepted 0.5 m/s, a deceleration of the request).
    assert_eq!(out_twist(&v).linear.x, 0.5);
    let v =
        f.fw.check(&twist_cmd(f.nav, f.base, T + 2, vx(f64::NAN)), T + 2);
    assert!(v.output().unwrap().motion.is_zero());
}
