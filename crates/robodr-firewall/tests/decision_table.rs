//! Row-by-row tests of the decision table in the crate docs, plus precedence,
//! fail behaviours, observe mode, joints, rate/accel/jerk maths and reporting.

mod common;
use common::*;
use robodr_events::Severity;
use robodr_firewall::*;

fn reason(v: &Verdict) -> RejectReason {
    v.reject_reason()
        .unwrap_or_else(|| panic!("expected reject, got {v:?}"))
}

// ------------------------------------------------------------------ pass

#[test]
fn within_envelope_passes_bit_exact() {
    let mut f = default_fx();
    let cmd = twist_cmd(f.nav, f.base, T0, tw(0.3, 0.1, 0.0, 0.0, 0.0, 0.5));
    assert_eq!(
        f.fw.check(&cmd, T0),
        Verdict::Passed {
            cmd,
            would_have: None
        }
    );
    assert!(f.fw.events().is_empty());
    let j = joint_cmd(f.arm_src, f.arm, T0, &[0.1, -0.2, 0.3, 1.5, -1.5, 0.0]);
    assert_eq!(
        f.fw.check(&j, T0),
        Verdict::Passed {
            cmd: j,
            would_have: None
        }
    );
    assert_eq!(f.fw.stats().passed, 2);
}

#[test]
fn exactly_at_limit_passes() {
    let mut f = default_fx();
    let v = f.fw.check(
        &twist_cmd(f.nav, f.base, T0, tw(LIN, 0.0, 0.0, 0.0, 0.0, ANG)),
        T0,
    );
    assert!(v.is_passed(), "{v:?}");
}

// ------------------------------------------------------------------ stage 0-2

#[test]
fn clock_regression_rejected_and_not_adopted() {
    let mut f = default_fx();
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0, vx(0.1)), T0)
        .is_passed());
    let v =
        f.fw.check(&twist_cmd(f.nav, f.base, T0 - MS, vx(0.1)), T0 - MS);
    assert_eq!(reason(&v), RejectReason::ClockRegression);
    // The regressed time was not adopted: T0+1ms is still fine.
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0 + MS, vx(0.1)), T0 + MS)
        .is_passed());
}

#[test]
fn unknown_channel_rejected_without_substitute() {
    let mut f = default_fx();
    let v =
        f.fw.check(&twist_cmd(f.nav, ChannelId(77), T0, vx(0.1)), T0);
    assert_eq!(
        v,
        Verdict::Rejected {
            reason: RejectReason::UnknownChannel,
            substitute: None
        }
    );
}

#[test]
fn unknown_source_rejected() {
    let mut f = default_fx();
    for src in [SourceId::UNKNOWN, SourceId(200), SourceId::FIREWALL] {
        let v = f.fw.check(&twist_cmd(src, f.base, T0, vx(0.1)), T0);
        assert_eq!(reason(&v), RejectReason::UnknownSource);
        // Default ForeignSourceAction::Substitute + ZeroVelocity.
        assert!(v.output().unwrap().motion.is_zero());
    }
    assert_eq!(f.fw.source_id(&guid("deadbeef")), None);
}

#[test]
fn source_ids_resolve_case_insensitively() {
    let f = default_fx();
    assert_eq!(
        f.fw.source_id(&guid("00000103").to_uppercase()),
        Some(f.nav)
    );
}

#[test]
fn unauthorized_source_rejected() {
    let mut f = default_fx();
    let v = f.fw.check(&twist_cmd(f.arm_src, f.base, T0, vx(0.1)), T0);
    assert_eq!(reason(&v), RejectReason::UnauthorizedSource);
    let v =
        f.fw.check(&joint_cmd(f.nav, f.arm, T0, &[0.0; ARM_JOINTS]), T0);
    assert_eq!(reason(&v), RejectReason::UnauthorizedSource);
}

#[test]
fn foreign_source_drop_emits_nothing_but_other_rejections_still_substitute() {
    let mut f = build(
        PlatformConfig {
            foreign_source_action: ForeignSourceAction::Drop,
            ..Default::default()
        },
        true,
        |_, _| {},
    );
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0, vx(0.5)), T0)
        .is_passed());
    let v = f.fw.check(
        &twist_cmd(SourceId::UNKNOWN, f.base, T0 + MS, vx(9.0)),
        T0 + MS,
    );
    assert_eq!(
        v,
        Verdict::Rejected {
            reason: RejectReason::UnknownSource,
            substitute: None
        }
    );
    // The legit stream is unaffected (its state was not reset to zero).
    let v =
        f.fw.check(&twist_cmd(f.nav, f.base, T0 + 2 * MS, vx(0.5)), T0 + 2 * MS);
    assert!(v.is_passed());
    // A NaN from the legit source still gets the substitute.
    let v = f.fw.check(
        &twist_cmd(f.nav, f.base, T0 + 3 * MS, vx(f64::NAN)),
        T0 + 3 * MS,
    );
    assert_eq!(reason(&v), RejectReason::NonFinite);
    assert!(v.output().unwrap().motion.is_zero());
    // Still recorded.
    assert!(f.fw.events().as_slice().iter().any(
        |e| e.rule == rules::REJECTED_UNKNOWN_SOURCE && e.action == EventAction::Rejected(None)
    ));
}

// ------------------------------------------------------------------ stage 3: rate

#[test]
fn rate_limit_token_bucket_math() {
    // 10/s => cost 100 ms of credit; burst 2 => capacity 200 ms.
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.rate_limit = Some(RateLimit {
            per_second: 10,
            burst: 2,
        })
    });
    let mut t = T0;
    let send = |f: &mut Fx, t: u64| f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.1)), t);
    assert!(send(&mut f, t).is_passed()); // credit 200 -> 100
    t += MS;
    assert!(send(&mut f, t).is_passed()); // 100+1 -> 1
    t += MS;
    assert_eq!(reason(&send(&mut f, t)), RejectReason::RateLimited); // 2 < 100
    t += 97 * MS;
    assert_eq!(reason(&send(&mut f, t)), RejectReason::RateLimited); // 99 < 100
    t += MS;
    assert!(send(&mut f, t).is_passed()); // 100 -> 0
                                          // Sustained 10 Hz is fine forever.
    for _ in 0..50 {
        t += 100 * MS;
        assert!(send(&mut f, t).is_passed());
    }
    // Credit is capped at burst: after a long idle, only 2 back-to-back.
    t += 10_000 * MS;
    assert!(send(&mut f, t).is_passed());
    assert!(send(&mut f, t + 1).is_passed());
    assert_eq!(reason(&send(&mut f, t + 2)), RejectReason::RateLimited);
}

#[test]
fn rate_limit_is_per_source() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.rate_limit = Some(RateLimit {
            per_second: 1,
            burst: 1,
        })
    });
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0, vx(0.1)), T0)
        .is_passed());
    let t = T0 + MS;
    assert_eq!(
        reason(&f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.1)), t)),
        RejectReason::RateLimited
    );
    assert!(f
        .fw
        .check(&twist_cmd(f.teleop, f.base, t, vx(0.1)), t)
        .is_passed());
}

#[test]
fn foreign_flood_does_not_consume_legit_rate() {
    let mut f = build(
        PlatformConfig {
            foreign_source_action: ForeignSourceAction::Drop,
            ..Default::default()
        },
        true,
        |b, _| {
            b.rate_limit = Some(RateLimit {
                per_second: 1,
                burst: 1,
            })
        },
    );
    for i in 0..100 {
        f.fw.check(
            &twist_cmd(SourceId::UNKNOWN, f.base, T0 + i, vx(0.1)),
            T0 + i,
        );
        f.fw.check(&twist_cmd(f.arm_src, f.base, T0 + i, vx(0.1)), T0 + i);
    }
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0 + 100, vx(0.1)), T0 + 100)
        .is_passed());
}

// ------------------------------------------------------------------ stage 4-5

#[test]
fn kind_mismatch_rejected() {
    let mut f = default_fx();
    let v = f.fw.check(&joint_cmd(f.nav, f.base, T0, &[0.0; 6]), T0);
    assert_eq!(reason(&v), RejectReason::KindMismatch);
    let v = f.fw.check(&twist_cmd(f.arm_src, f.arm, T0, vx(0.0)), T0);
    assert_eq!(reason(&v), RejectReason::KindMismatch);
    for n in [0, 5, 7, MAX_JOINTS] {
        let v =
            f.fw.check(&joint_cmd(f.arm_src, f.arm, T0, &vec![0.0; n]), T0);
        assert_eq!(reason(&v), RejectReason::KindMismatch, "n={n}");
    }
}

#[test]
fn non_finite_rejected_in_every_component() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        for i in 0..6 {
            let mut f = default_fx();
            let mut c = [0.1; 6];
            c[i] = bad;
            let t = tw(c[0], c[1], c[2], c[3], c[4], c[5]);
            let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, t), T0);
            assert_eq!(reason(&v), RejectReason::NonFinite, "component {i} = {bad}");
            assert!(v.output().unwrap().motion.is_zero());
        }
        for i in 0..ARM_JOINTS {
            let mut f = default_fx();
            let mut j = [0.1; ARM_JOINTS];
            j[i] = bad;
            let v = f.fw.check(&joint_cmd(f.arm_src, f.arm, T0, &j), T0);
            assert_eq!(reason(&v), RejectReason::NonFinite);
            assert_eq!(out_joints(&v), vec![0.0; ARM_JOINTS]);
        }
    }
}

// ------------------------------------------------------------------ stage 6: time

#[test]
fn future_timestamp_boundary() {
    let mut f = default_fx();
    let max_future = ChannelSpec::default().max_future_ns;
    let ok =
        f.fw.check(&twist_cmd(f.nav, f.base, T0 + max_future, vx(0.1)), T0);
    assert!(ok.is_passed());
    let v = f.fw.check(
        &twist_cmd(f.teleop, f.base, T0 + max_future + 1, vx(0.1)),
        T0,
    );
    assert_eq!(reason(&v), RejectReason::FutureTimestamp);
    let v =
        f.fw.check(&twist_cmd(f.teleop, f.base, u64::MAX, vx(0.1)), T0);
    assert_eq!(reason(&v), RejectReason::FutureTimestamp);
}

#[test]
fn stale_timestamp_boundary() {
    let mut f = default_fx();
    let max_age = ChannelSpec::default().max_age_ns;
    let ok =
        f.fw.check(&twist_cmd(f.nav, f.base, T0 - max_age, vx(0.1)), T0);
    assert!(ok.is_passed());
    let v =
        f.fw.check(&twist_cmd(f.teleop, f.base, T0 - max_age - 1, vx(0.1)), T0);
    assert_eq!(reason(&v), RejectReason::Stale);
    let v = f.fw.check(&twist_cmd(f.teleop, f.base, 0, vx(0.1)), T0);
    assert_eq!(reason(&v), RejectReason::Stale);
    // Event carries age and limit.
    let ev = f.fw.events().as_slice().last().copied().unwrap();
    assert_eq!(ev.rule, rules::REJECTED_STALE);
    assert_eq!(ev.value, T0 as f64);
    assert_eq!(ev.limit, max_age as f64);
}

#[test]
fn replay_and_reorder_rejected_per_source() {
    let mut f = default_fx();
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0, vx(0.1)), T0)
        .is_passed());
    let t = T0 + MS;
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(0.1)), t);
    assert_eq!(reason(&v), RejectReason::OutOfOrder);
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0 - 1, vx(0.1)), t);
    assert_eq!(reason(&v), RejectReason::OutOfOrder);
    // Another source has its own sequence.
    assert!(f
        .fw
        .check(&twist_cmd(f.teleop, f.base, T0 - 5 * MS, vx(0.1)), t)
        .is_passed());
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0 + 1, vx(0.1)), t)
        .is_passed());
}

#[test]
fn replay_of_hard_rejected_command_is_still_a_replay() {
    let mut f = default_fx();
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(50.0)), T0);
    assert_eq!(reason(&v), RejectReason::OverHardLimit);
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(0.1)), T0 + 1);
    assert_eq!(reason(&v), RejectReason::OutOfOrder);
}

// ------------------------------------------------------------------ stage 7-8a: speed

#[test]
fn over_hard_factor_rejected_at_boundary() {
    let mut f = default_fx();
    let mut t = T0;
    let mut go = |f: &mut Fx, tw: Twist| {
        t += MS;
        f.fw.check(&twist_cmd(f.nav, f.base, t, tw), t)
    };
    assert!(go(&mut f, vx(2.0 * LIN)).is_limited());
    assert_eq!(
        reason(&go(&mut f, vx(2.0 * LIN + 1e-9))),
        RejectReason::OverHardLimit
    );
    assert_eq!(
        reason(&go(&mut f, tw(0.0, 0.0, 0.0, 0.0, 0.0, -2.0 * ANG - 1e-9))),
        RejectReason::OverHardLimit
    );
    assert_eq!(reason(&go(&mut f, vx(1e300))), RejectReason::OverHardLimit);
    assert_eq!(
        reason(&go(&mut f, vx(f64::MAX))),
        RejectReason::OverHardLimit
    );
    let v = f.fw.check(
        &joint_cmd(
            f.arm_src,
            f.arm,
            T0 + 100 * MS,
            &[0.0, 0.0, 0.0, 0.0, 0.0, -3.01],
        ),
        T0 + 100 * MS,
    );
    assert_eq!(reason(&v), RejectReason::OverHardLimit);
}

#[test]
fn custom_hard_factor() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.hard_reject_factor = 1.0
    });
    let v =
        f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(LIN * 1.0001)), T0);
    assert_eq!(reason(&v), RejectReason::OverHardLimit);
}

#[test]
fn over_speed_scaled_preserving_direction() {
    let mut f = default_fx();
    let input = tw(1.2, -0.9, 0.0, 0.0, 0.0, 0.0); // |v| = 1.5
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, input), T0);
    let Verdict::Limited { cmd, reasons } = v else {
        panic!("{v:?}")
    };
    assert_eq!(reasons, LimitReasons::SPEED);
    let Motion::Twist(o) = cmd.motion else {
        panic!()
    };
    assert!(norm3(o.linear) <= LIN);
    assert!((norm3(o.linear) - LIN).abs() < 1e-12);
    // Same direction: cross product zero, positive dot product.
    assert!((o.linear.x * input.linear.y - o.linear.y * input.linear.x).abs() < 1e-12);
    assert!(o.linear.x * input.linear.x > 0.0);
    // Everything else in the command is untouched.
    assert_eq!(cmd.source, f.nav);
    assert_eq!(cmd.stamp_ns, T0);
}

#[test]
fn speed_scaling_is_uniform_and_preserves_curvature() {
    let mut f = default_fx();
    // Linear 1.5x over, angular within its own limit.
    let input = tw(1.5, 0.0, 0.0, 0.0, 0.0, 1.2);
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, input), T0);
    let o = out_twist(&v);
    let k_in = input.angular.z / input.linear.x;
    let k_out = o.angular.z / o.linear.x;
    assert!((k_in - k_out).abs() < 1e-12, "turn radius changed");
    assert!(o.angular.z < 1.2);
    // Angular is the binding group this time.
    let input = tw(0.5, 0.0, 0.0, 0.0, 0.0, 3.0);
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0 + 1, input), T0 + 1);
    let o = out_twist(&v);
    assert!((norm3(o.angular) - ANG).abs() < 1e-12);
    assert!((o.linear.x - 0.5 * ANG / 3.0).abs() < 1e-12);
}

#[test]
fn joints_scaled_together() {
    let mut f = default_fx();
    let input = [3.0, -1.5, 0.75, 0.0, 0.3, -2.0]; // max 3.0 = 2x
    let v = f.fw.check(&joint_cmd(f.arm_src, f.arm, T0, &input), T0);
    assert!(v.is_limited());
    let o = out_joints(&v);
    for (a, b) in o.iter().zip(input) {
        assert!((a - b / 2.0).abs() < 1e-12);
        assert!(a.abs() <= JOINT);
    }
}

#[test]
fn spec_can_tighten_envelope() {
    let mut f = build(PlatformConfig::default(), true, |b, a| {
        b.max_linear_speed = Some(0.25);
        a.max_joint_speed = Some(0.5);
    });
    let o = out_twist(&f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(0.4)), T0));
    assert!((o.linear.x - 0.25).abs() < 1e-12);
    let v =
        f.fw.check(&twist_cmd(f.nav, f.base, T0 + 1, vx(0.6)), T0 + 1);
    assert_eq!(reason(&v), RejectReason::OverHardLimit);
    let o = out_joints(&f.fw.check(
        &joint_cmd(f.arm_src, f.arm, T0 + 2, &[0.0, 0.0, 0.0, 0.0, 0.0, 0.8]),
        T0 + 2,
    ));
    assert!((o[5] - 0.5).abs() < 1e-12);
}

#[test]
fn zero_limit_means_no_motion() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.max_angular_speed = Some(0.0)
    });
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, T0, vx(0.5)), T0)
        .is_passed());
    let v = f.fw.check(
        &twist_cmd(f.nav, f.base, T0 + 1, tw(0.5, 0.0, 0.0, 0.0, 0.0, 1e-6)),
        T0 + 1,
    );
    assert_eq!(reason(&v), RejectReason::OverHardLimit);
}

// ------------------------------------------------------------------ precedence

#[test]
fn stage_precedence() {
    let mut f = default_fx();
    // Unknown source beats NaN.
    let v =
        f.fw.check(&twist_cmd(SourceId::UNKNOWN, f.base, T0, vx(f64::NAN)), T0);
    assert_eq!(reason(&v), RejectReason::UnknownSource);
    // Kind beats NaN.
    let v = f.fw.check(&joint_cmd(f.nav, f.base, T0, &[f64::NAN]), T0);
    assert_eq!(reason(&v), RejectReason::KindMismatch);
    // NaN beats stale.
    let v = f.fw.check(&twist_cmd(f.nav, f.base, 0, vx(f64::NAN)), T0);
    assert_eq!(reason(&v), RejectReason::NonFinite);
    // Stale beats over-hard.
    let v = f.fw.check(&twist_cmd(f.nav, f.base, 0, vx(100.0)), T0);
    assert_eq!(reason(&v), RejectReason::Stale);
    // Unknown channel beats unknown source.
    let v =
        f.fw.check(&twist_cmd(SourceId::UNKNOWN, ChannelId(9), T0, vx(0.0)), T0);
    assert_eq!(reason(&v), RejectReason::UnknownChannel);
}

#[test]
fn rate_limit_precedes_content_checks() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.rate_limit = Some(RateLimit {
            per_second: 1,
            burst: 1,
        })
    });
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(f64::NAN)), T0);
    assert_eq!(reason(&v), RejectReason::NonFinite); // consumed the token
    let v =
        f.fw.check(&twist_cmd(f.nav, f.base, T0 + 1, vx(f64::NAN)), T0 + 1);
    assert_eq!(reason(&v), RejectReason::RateLimited);
}

// ------------------------------------------------------------------ stage 8b: accel / jerk

fn accel_fx() -> Fx {
    build(PlatformConfig::default(), true, |b, a| {
        b.max_linear_accel = Some(1.0); // m/s²
        b.max_angular_accel = Some(2.0);
        a.max_joint_accel = Some(3.0);
    })
}

#[test]
fn acceleration_rate_limits_ramp_from_rest() {
    let mut f = accel_fx();
    let step = 100 * MS; // == default dt cap
    let mut t = T0;
    for k in 1..=10 {
        let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t);
        let o = out_twist(&v);
        let expect = 0.1 * k as f64;
        assert!(
            (o.linear.x - expect).abs() < 1e-9,
            "k={k}: {} vs {expect}",
            o.linear.x
        );
        if k < 10 {
            let Verdict::Limited { reasons, .. } = v else {
                panic!("{v:?}")
            };
            assert_eq!(reasons, LimitReasons::ACCELERATION);
        }
        t += step;
    }
    // At target now: passes.
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t)
        .is_passed());
}

#[test]
fn acceleration_uses_gateway_clock_not_source_stamp() {
    let mut f = accel_fx();
    // Source claims 100 ms between commands, but they arrive 10 ms apart.
    let o1 = out_twist(
        &f.fw
            .check(&twist_cmd(f.nav, f.base, T0, vx(1.0)), T0 + 100 * MS),
    );
    let o2 = out_twist(&f.fw.check(
        &twist_cmd(f.nav, f.base, T0 + 100 * MS, vx(1.0)),
        T0 + 110 * MS,
    ));
    assert!((o1.linear.x - 0.1).abs() < 1e-9);
    assert!((o2.linear.x - 0.11).abs() < 1e-9, "{}", o2.linear.x);
}

#[test]
fn acceleration_preserves_direction_of_change() {
    let mut f = accel_fx();
    let o = out_twist(&f.fw.check(
        &twist_cmd(f.nav, f.base, T0, tw(0.6, 0.8, 0.0, 0.0, 0.0, 0.0)),
        T0,
    ));
    assert!((norm3(o.linear) - 0.1).abs() < 1e-9);
    assert!((o.linear.x / o.linear.y - 0.75).abs() < 1e-9);
}

#[test]
fn stop_is_never_delayed_by_default() {
    let mut f = accel_fx();
    let mut t = T0;
    for _ in 0..10 {
        f.fw.check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t);
        t += 100 * MS;
    }
    let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.0)), t);
    assert!(v.is_passed(), "{v:?}");
    // Partial slow-down also immediate.
    let mut f = accel_fx();
    let mut t = T0;
    for _ in 0..10 {
        f.fw.check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t);
        t += 100 * MS;
    }
    assert!(f
        .fw
        .check(&twist_cmd(f.nav, f.base, t, vx(0.2)), t)
        .is_passed());
}

#[test]
fn reversal_is_not_a_deceleration() {
    let mut f = accel_fx();
    let mut t = T0;
    for _ in 0..5 {
        f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.5)), t);
        t += 100 * MS;
    }
    let o = out_twist(&f.fw.check(&twist_cmd(f.nav, f.base, t, vx(-0.5)), t));
    assert!((o.linear.x - 0.4).abs() < 1e-9, "{}", o.linear.x);
}

#[test]
fn deceleration_limited_when_configured() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.max_linear_accel = Some(1.0);
        b.limit_deceleration = true;
    });
    let mut t = T0;
    for _ in 0..10 {
        f.fw.check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t);
        t += 100 * MS;
    }
    let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.0)), t);
    assert!(v.is_limited());
    assert!((out_twist(&v).linear.x - 0.9).abs() < 1e-9);
}

#[test]
fn state_resets_to_rest_after_gap() {
    let mut f = accel_fx();
    let mut t = T0;
    for _ in 0..10 {
        f.fw.check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t);
        t += 100 * MS;
    }
    t += ChannelSpec::default().state_reset_after_ns + 1;
    let o = out_twist(&f.fw.check(&twist_cmd(f.nav, f.base, t, vx(1.0)), t));
    assert!((o.linear.x - 0.1).abs() < 1e-9, "{}", o.linear.x);
}

#[test]
fn same_instant_commands_cannot_accelerate() {
    let mut f = accel_fx();
    let o = out_twist(&f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(1.0)), T0));
    let o2 = out_twist(&f.fw.check(&twist_cmd(f.nav, f.base, T0 + 1, vx(1.0)), T0));
    assert_eq!(o.linear.x, o2.linear.x);
}

#[test]
fn joint_acceleration_per_joint() {
    let mut f = accel_fx();
    // 3 rad/s² × 0.1 s = 0.3 rad/s per step on the fastest joint.
    let v = f.fw.check(
        &joint_cmd(f.arm_src, f.arm, T0, &[1.2, 0.6, 0.0, 0.0, 0.0, -0.3]),
        T0,
    );
    let o = out_joints(&v);
    assert!((o[0] - 0.3).abs() < 1e-9);
    assert!((o[1] - 0.15).abs() < 1e-9);
    assert!((o[5] + 0.075).abs() < 1e-9);
}

#[test]
fn jerk_bounds_growth_of_acceleration() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.max_linear_jerk = Some(10.0); // m/s³
    });
    // dt = 0.1: a_k ≤ a_{k-1} + 1.0 → Δv = 0.1, 0.2, 0.3, ...
    let mut t = T0;
    let mut expect = 0.0;
    for k in 1..=3 {
        let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(LIN)), t);
        expect += 0.1 * k as f64;
        let o = out_twist(&v);
        assert!((o.linear.x - expect).abs() < 1e-9, "k={k}: {}", o.linear.x);
        let Verdict::Limited { reasons, .. } = v else {
            panic!("{v:?}")
        };
        assert!(reasons.contains(LimitReasons::JERK));
        t += 100 * MS;
    }
    // 0.6 + 0.4 reaches the target exactly: passes.
    let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(LIN)), t);
    assert!(v.is_passed(), "{v:?}");
    let ev = f.fw.events().as_slice();
    assert_eq!(ev.len(), 3);
    assert!(ev.iter().all(|e| e.rule == rules::LIMITED_JERK));
}

#[test]
fn speed_and_acceleration_reasons_combine() {
    let mut f = accel_fx();
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(1.5)), T0);
    let Verdict::Limited { reasons, cmd } = v else {
        panic!("{v:?}")
    };
    assert!(reasons.contains(LimitReasons::SPEED | LimitReasons::ACCELERATION));
    let Motion::Twist(o) = cmd.motion else {
        panic!()
    };
    assert!((o.linear.x - 0.1).abs() < 1e-9);
    let rules: Vec<_> = f.fw.events().as_slice().iter().map(|e| e.rule).collect();
    assert_eq!(
        rules,
        vec![rules::LIMITED_SPEED, rules::LIMITED_ACCELERATION]
    );
}

// ------------------------------------------------------------------ fail behaviour

fn hold_fx(max_hold_ns: u64) -> Fx {
    build(
        PlatformConfig {
            fail_behaviour: FailBehaviour::HoldLast { max_hold_ns },
            ..Default::default()
        },
        true,
        |_, _| {},
    )
}

#[test]
fn zero_velocity_substitute() {
    let mut f = default_fx();
    f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(0.5)), T0);
    let v = f.fw.check(
        &twist_cmd(f.nav, f.base, T0 + MS, vx(f64::NAN)),
        T0 + 2 * MS,
    );
    let Verdict::Rejected {
        substitute: Some(s),
        ..
    } = v
    else {
        panic!("{v:?}")
    };
    assert_eq!(s.kind, SubstituteKind::Zero);
    assert_eq!(s.cmd.source, SourceId::FIREWALL);
    assert_eq!(s.cmd.stamp_ns, T0 + 2 * MS);
    assert_eq!(s.cmd.channel, f.base);
    assert_eq!(s.cmd.motion, Motion::Twist(Twist::ZERO));
}

#[test]
fn hold_last_holds_last_accepted_then_expires() {
    let mut f = hold_fx(50 * MS);
    let accepted = out_twist(&f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(1.5)), T0));
    assert!((accepted.linear.x - LIN).abs() < 1e-12); // limited output is what is held
    for dt in [MS, 10 * MS, 50 * MS] {
        let t = T0 + dt;
        let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(9.0)), t);
        let Verdict::Rejected {
            substitute: Some(s),
            ..
        } = v
        else {
            panic!("{v:?}")
        };
        assert_eq!(s.kind, SubstituteKind::HoldLast, "dt={dt}");
        assert_eq!(s.cmd.motion, Motion::Twist(accepted));
    }
    // Rejections did not extend the hold window.
    let t = T0 + 50 * MS + 1;
    let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(9.0)), t);
    let Verdict::Rejected {
        substitute: Some(s),
        ..
    } = v
    else {
        panic!("{v:?}")
    };
    assert_eq!(s.kind, SubstituteKind::Zero);
    assert!(s.cmd.motion.is_zero());
}

#[test]
fn hold_last_with_nothing_accepted_is_zero() {
    let mut f = hold_fx(1_000 * MS);
    let v = f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(f64::NAN)), T0);
    let Verdict::Rejected {
        substitute: Some(s),
        ..
    } = v
    else {
        panic!("{v:?}")
    };
    assert_eq!(s.kind, SubstituteKind::Zero);
}

#[test]
fn hold_last_for_joints() {
    let mut f = hold_fx(1_000 * MS);
    let good = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6];
    f.fw.check(&joint_cmd(f.arm_src, f.arm, T0, &good), T0);
    let v = f.fw.check(
        &joint_cmd(f.arm_src, f.arm, T0 + 1, &[f64::NAN; ARM_JOINTS]),
        T0 + 1,
    );
    assert_eq!(out_joints(&v), good.to_vec());
}

#[test]
fn pass_through_platform_never_enforces() {
    let mut f = build(
        PlatformConfig {
            fail_behaviour: FailBehaviour::PassThroughObserveOnly,
            ..Default::default()
        },
        true,
        |b, _| b.max_linear_accel = Some(1.0),
    );
    assert!(!f.fw.is_enforcing());
    for (i, t) in [vx(1.5), vx(5.0), vx(f64::NAN)].into_iter().enumerate() {
        let now = T0 + i as u64;
        let cmd = twist_cmd(f.nav, f.base, now, t);
        let v = f.fw.check(&cmd, now);
        let Verdict::Passed {
            cmd: out,
            would_have: Some(_),
        } = v
        else {
            panic!("{v:?}")
        };
        assert_eq!(out.motion.is_finite(), cmd.motion.is_finite());
        if cmd.motion.is_finite() {
            assert_eq!(out, cmd);
        }
    }
    assert!(f
        .fw
        .events()
        .as_slice()
        .iter()
        .all(|e| e.action == EventAction::ObservedOnly));
}

// ------------------------------------------------------------------ observe mode

#[test]
fn observe_mode_passes_everything_and_records_would_have() {
    let mut f = build(PlatformConfig::default(), false, |_, _| {});
    assert!(!f.fw.is_enforcing());

    let c = twist_cmd(f.nav, f.base, T0, vx(1.5));
    let Verdict::Passed {
        cmd,
        would_have: Some(WouldHave::Limited { cmd: lim, reasons }),
    } = f.fw.check(&c, T0)
    else {
        panic!()
    };
    assert_eq!(cmd, c);
    assert_eq!(reasons, LimitReasons::SPEED);
    let Motion::Twist(lt) = lim.motion else {
        panic!()
    };
    assert!((lt.linear.x - LIN).abs() < 1e-12);

    let c = twist_cmd(SourceId::UNKNOWN, f.base, T0 + 1, vx(0.1));
    assert_eq!(
        f.fw.check(&c, T0 + 1),
        Verdict::Passed {
            cmd: c,
            would_have: Some(WouldHave::Rejected {
                reason: RejectReason::UnknownSource
            })
        }
    );
    let c = twist_cmd(f.nav, f.base, T0 + 2, vx(0.1));
    assert_eq!(
        f.fw.check(&c, T0 + 2),
        Verdict::Passed {
            cmd: c,
            would_have: None
        }
    );
    let st = f.fw.stats();
    assert_eq!(
        (st.passed, st.limited, st.rejected, st.would_have),
        (3, 0, 0, 2)
    );
    let devs = f.fw.drain_deviations();
    assert_eq!(devs.len(), 2);
    assert!(devs.iter().all(|d| d.detail.contains("observe only")));
}

// ------------------------------------------------------------------ reporting

#[test]
fn deviations_have_rules_severities_and_names() {
    let mut f = default_fx();
    f.fw.check(&twist_cmd(SourceId::UNKNOWN, f.base, T0, vx(0.1)), T0);
    f.fw.check(&twist_cmd(f.nav, f.base, T0 + 1, vx(1.5)), T0 + 1);
    f.fw.check(&twist_cmd(f.arm_src, f.base, T0 + 2, vx(0.1)), T0 + 2);
    let devs = f.fw.drain_deviations();
    assert_eq!(devs.len(), 3);
    assert_eq!(devs[0].rule, "robot.firewall.rejected_unknown_source");
    assert_eq!(devs[0].severity, Severity::Critical);
    assert!(devs[0].detail.contains("/cmd_vel"));
    assert!(devs[0].detail.contains("<unknown source>"));
    assert!(devs[0].detail.contains("zero velocity emitted"));
    assert_eq!(devs[1].rule, "robot.firewall.limited_speed");
    assert_eq!(devs[1].severity, Severity::High);
    assert!(devs[1].detail.contains(&guid("00000103")));
    assert!(devs[1].detail.contains("value 1.500000 limit 1.000000"));
    assert_eq!(devs[2].rule, "robot.firewall.rejected_unauthorized_source");
    assert!(devs[2].detail.contains(&guid("00000303")));
    assert!(f.fw.events().is_empty());
}

#[test]
fn full_event_buffer_drops_and_reports() {
    let mut f = build(
        PlatformConfig {
            event_capacity: 4,
            ..Default::default()
        },
        true,
        |_, _| {},
    );
    for i in 0..10 {
        f.fw.check(
            &twist_cmd(SourceId::UNKNOWN, f.base, T0 + i, vx(0.0)),
            T0 + i,
        );
    }
    assert_eq!(f.fw.events().len(), 4);
    assert_eq!(f.fw.events().dropped(), 6);
    let devs = f.fw.drain_deviations();
    assert_eq!(devs.len(), 5);
    assert_eq!(devs[4].rule, rules::EVENTS_DROPPED);
    assert!(devs[4].detail.starts_with("6 "));
    // Drained: buffer usable again, counter reset.
    f.fw.check(
        &twist_cmd(SourceId::UNKNOWN, f.base, T0 + 20, vx(0.0)),
        T0 + 20,
    );
    let mut n = 0;
    assert_eq!(f.fw.drain_events(|_| n += 1), 0);
    assert_eq!(n, 1);
}

#[test]
fn stats_count_verdicts() {
    let mut f = default_fx();
    f.fw.check(&twist_cmd(f.nav, f.base, T0, vx(0.1)), T0);
    f.fw.check(&twist_cmd(f.nav, f.base, T0 + 1, vx(1.1)), T0 + 1);
    f.fw.check(&twist_cmd(f.nav, f.base, T0 + 2, vx(f64::NAN)), T0 + 2);
    let s = f.fw.stats();
    assert_eq!(
        (s.checked, s.passed, s.limited, s.rejected, s.faults),
        (3, 1, 1, 1, 0)
    );
}

#[test]
fn policy_accessors() {
    let f = default_fx();
    let p = f.fw.policy();
    assert_eq!(p.model(), "ugv-test");
    assert!(p.profile_locked());
    assert_eq!(p.channel_name(f.base), Some("/cmd_vel"));
    assert_eq!(
        p.source_guid(f.nav).map(str::to_owned),
        Some(guid("00000103"))
    );
    assert_eq!(*p.platform(), PlatformConfig::default());
    assert_eq!(p.platform().fault_policy, FaultPolicy::FailSafe);
}
