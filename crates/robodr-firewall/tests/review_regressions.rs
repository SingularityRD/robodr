//! Regression tests for the wave-2 safety review findings.
//!
//! Each test is a port of a reviewer PoC (which passed while the issue
//! existed) rewritten to assert the fixed behaviour.

use robodr_events::profile::{Envelope, Profile};
use robodr_events::Mode;
use robodr_firewall::*;
use std::collections::BTreeMap;

const PREFIX: &str = "0123456789abcdef01234567";
const MS: u64 = 1_000_000;
const T0: u64 = 1_000 * MS;

fn profile(lin: Option<f64>, locked: bool) -> Profile {
    let mut p = Profile {
        model: "ugv".into(),
        locked,
        ..Default::default()
    };
    p.participants.insert(PREFIX.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: lin,
            max_joint_speed: None,
        },
    );
    p
}

fn compile(
    lin: Option<f64>,
    locked: bool,
    platform: PlatformConfig,
    spec: ChannelSpec,
) -> Result<Policy, ConfigError> {
    let specs = BTreeMap::from([("/cmd_vel".to_string(), spec)]);
    Policy::compile(&profile(lin, locked), platform, &specs)
}

fn fw(
    lin: Option<f64>,
    locked: bool,
    platform: PlatformConfig,
    spec: ChannelSpec,
) -> (Firewall, SourceId, ChannelId) {
    let f = Firewall::new(compile(lin, locked, platform, spec).expect("compiles"));
    let s = f.source_id(&format!("{PREFIX}00000103")).unwrap();
    let c = f.channel_id("/cmd_vel").unwrap();
    (f, s, c)
}

/// Spec with the (now mandatory) angular limit.
fn spec() -> ChannelSpec {
    ChannelSpec {
        kind: ChannelKind::Twist,
        allowed_sources: vec![format!("{PREFIX}00000103")],
        max_angular_speed: Some(1.0),
        ..Default::default()
    }
}

fn tw(lx: f64, az: f64) -> Twist {
    Twist::new(Vec3::new(lx, 0.0, 0.0), Vec3::new(0.0, 0.0, az))
}

fn out_twist(v: &Verdict) -> Twist {
    match v.output().expect("something emitted").motion {
        Motion::Twist(t) => t,
        m => panic!("not a twist: {m:?}"),
    }
}

fn sub_kind(v: &Verdict) -> SubstituteKind {
    match v {
        Verdict::Rejected {
            substitute: Some(s),
            ..
        } => s.kind,
        v => panic!("no substitute: {v:?}"),
    }
}

// ------------------------------------------------- finding 2: angular bound

/// Was: a Twist channel without `max_angular_speed` passed 1e6 rad/s.
/// Now: such a policy does not compile.
#[test]
fn angular_limit_is_required_for_twist_channels() {
    let no_ang = ChannelSpec {
        max_angular_speed: None,
        ..spec()
    };
    assert_eq!(
        compile(Some(0.5), true, PlatformConfig::default(), no_ang),
        Err(ConfigError::MissingLimit {
            channel: "/cmd_vel".into(),
            field: "max_angular_speed",
        })
    );
    // With the limit spelled out, 1e6 rad/s is far over the hard limit.
    let (mut f, s, c) = fw(Some(0.5), true, PlatformConfig::default(), spec());
    let v = f.check(&Command::twist(s, c, T0, tw(0.1, 1.0e6)), T0);
    assert_eq!(v.reject_reason(), Some(RejectReason::OverHardLimit));
    assert!(out_twist(&v).angular.z.abs() <= 1.0);
}

// ---------------------------------- finding 4: HoldLast never moves a stop

fn holdlast() -> PlatformConfig {
    PlatformConfig {
        fail_behaviour: FailBehaviour::HoldLast {
            max_hold_ns: 1_000 * MS,
        },
        ..Default::default()
    }
}

/// Was: a legitimate stop rejected as rate-limited or stale was replaced by
/// the last accepted 0.9 m/s. Now: zero is emitted.
#[test]
fn holdlast_never_turns_a_rejected_stop_into_motion() {
    let sp = ChannelSpec {
        rate_limit: Some(RateLimit {
            per_second: 10,
            burst: 1,
        }),
        ..spec()
    };
    let (mut f, s, c) = fw(Some(1.0), true, holdlast(), sp);
    assert!(f
        .check(&Command::twist(s, c, T0, tw(0.9, 0.0)), T0)
        .is_passed());
    // Stop 5 ms later: rate-limited, and the substitute is zero.
    let v = f.check(
        &Command::twist(s, c, T0 + 5 * MS, tw(0.0, 0.0)),
        T0 + 5 * MS,
    );
    assert_eq!(v.reject_reason(), Some(RejectReason::RateLimited));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
    assert_eq!(out_twist(&v).linear.x, 0.0, "stop must stay a stop");
    // A stale stop (delayed by the network) is also zero, not 0.9 m/s.
    let v = f.check(&Command::twist(s, c, T0 + MS, tw(0.0, 0.0)), T0 + 400 * MS);
    assert!(v.is_rejected());
    assert_eq!(out_twist(&v).linear.x, 0.0);
}

/// A rejected *slow-down* or *reversal* is zero too; only a rejected
/// command that asked for at least the held motion (same direction) holds.
#[test]
fn holdlast_holds_only_when_it_is_no_more_than_requested() {
    let sp = ChannelSpec {
        max_age_ns: 100 * MS,
        ..spec()
    };
    let (mut f, s, c) = fw(Some(1.0), true, holdlast(), sp);
    let mut t = T0;
    assert!(f
        .check(&Command::twist(s, c, t, tw(0.6, 0.2)), t)
        .is_passed());
    // Stale, slower: zero.
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.3, 0.1)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::Stale));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
    // Stale, reversing: zero.
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(-0.6, 0.2)), t);
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
    // Stale, same direction and at least as fast: the hold (0.6, 0.2) is
    // a deceleration of what was asked, so it is allowed.
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.8, 0.2)), t);
    assert_eq!(sub_kind(&v), SubstituteKind::HoldLast);
    assert_eq!(out_twist(&v), tw(0.6, 0.2));
    // Unreadable own content (NaN, wrong kind): intent unknown, so zero.
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t, tw(f64::NAN, 0.0)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::NonFinite));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
    t += 10 * MS;
    let j = JointVelocities::from_slice(&[0.5; 6]).unwrap();
    let v = f.check(&Command::joints(s, c, t, j), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::KindMismatch));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
}

/// A foreign source never earns a hold either (opt-in `Substitute`).
#[test]
fn holdlast_foreign_substitute_is_zero() {
    let pf = PlatformConfig {
        foreign_source_action: ForeignSourceAction::Substitute,
        ..holdlast()
    };
    let (mut f, s, c) = fw(Some(1.0), true, pf, spec());
    assert!(f
        .check(&Command::twist(s, c, T0, tw(0.6, 0.0)), T0)
        .is_passed());
    let v = f.check(
        &Command::twist(SourceId::UNKNOWN, c, T0 + MS, tw(0.9, 0.0)),
        T0 + MS,
    );
    assert_eq!(v.reject_reason(), Some(RejectReason::UnknownSource));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
}

/// The randomized property, in miniature: for every rejection reason the
/// own source can trigger, a HoldLast substitute is never more than asked.
#[test]
fn holdlast_never_exceeds_any_rejected_request() {
    let sp = ChannelSpec {
        rate_limit: Some(RateLimit {
            per_second: 1_000,
            burst: 1,
        }),
        max_age_ns: 100 * MS,
        ..spec()
    };
    let (mut f, s, c) = fw(Some(1.0), true, holdlast(), sp);
    let mut t = T0;
    assert!(f
        .check(&Command::twist(s, c, t, tw(0.5, 0.5)), t)
        .is_passed());
    for (i, (lx, az)) in [(0.0, 0.0), (0.4, 0.5), (0.5, -0.5), (0.5, 0.0), (9.0, 9.0)]
        .into_iter()
        .enumerate()
    {
        t += 5 * MS;
        // Stale, out of order, future (the last request is also far over
        // the hard limit).
        let cases = [(t - 200 * MS, t), (T0, t), (t + 10_000 * MS, t)];
        for (stamp, now) in cases {
            let v = f.check(&Command::twist(s, c, stamp, tw(lx, az)), now);
            assert!(v.is_rejected(), "{i}: {v:?}");
            let o = out_twist(&v);
            for (got, asked) in [(o.linear.x, lx), (o.angular.z, az)] {
                assert!(
                    got == 0.0 || (got * asked > 0.0 && got.abs() <= asked.abs()),
                    "{i}: held {o:?} for request ({lx}, {az})"
                );
            }
        }
    }
}

// ------------------------------- finding 3: profile validated at compile

/// Was: an envelope of +inf (rejected by `Profile::validate`) compiled to
/// "unconstrained" and 1e9 m/s passed. Now: compilation fails.
#[test]
fn infinite_envelope_does_not_compile() {
    assert!(profile(Some(f64::INFINITY), true).validate().is_err());
    for bad in [f64::INFINITY, f64::NAN, -0.5] {
        let r = compile(Some(bad), true, PlatformConfig::default(), spec());
        assert!(
            matches!(r, Err(ConfigError::InvalidProfile(_))),
            "{bad}: {r:?}"
        );
    }
    // Explicit +inf in a spec is not a way to say "unconstrained" either.
    for field in 0..3 {
        let mut sp = spec();
        match field {
            0 => sp.max_linear_speed = Some(f64::INFINITY),
            1 => sp.max_angular_speed = Some(f64::INFINITY),
            _ => sp.max_linear_accel = Some(f64::INFINITY),
        }
        let r = compile(Some(1.0), true, PlatformConfig::default(), sp);
        assert!(matches!(r, Err(ConfigError::InvalidLimit { .. })), "{r:?}");
    }
}

// ---------------------------------------- finding 1: observe-mode events

/// Was: an unlocked profile produced `Mode::Enforce` deviations. Now they
/// are `Mode::Observe`, as is the events-dropped summary.
#[test]
fn observe_events_are_observe_deviations() {
    let pf = PlatformConfig {
        event_capacity: 1,
        ..Default::default()
    };
    let (mut f, s, c) = fw(Some(0.5), false, pf, spec());
    assert!(!f.is_enforcing());
    let _ = f.check(&Command::twist(s, c, T0, tw(5.0, 0.0)), T0);
    let _ = f.check(&Command::twist(s, c, T0 + MS, tw(5.0, 0.0)), T0 + MS);
    let devs = f.drain_deviations();
    assert_eq!(devs.len(), 2, "{devs:?}");
    assert!(devs.iter().any(|d| d.rule == rules::EVENTS_DROPPED));
    assert!(devs.iter().all(|d| d.mode == Mode::Observe), "{devs:?}");
}

#[test]
fn pass_through_platform_events_are_observe_deviations() {
    let pf = PlatformConfig {
        fail_behaviour: FailBehaviour::PassThroughObserveOnly,
        ..Default::default()
    };
    let (mut f, s, c) = fw(Some(0.5), true, pf, spec());
    let _ = f.check(&Command::twist(s, c, T0, tw(5.0, 0.0)), T0);
    let devs = f.drain_deviations();
    assert!(!devs.is_empty());
    assert!(devs.iter().all(|d| d.mode == Mode::Observe), "{devs:?}");
}

#[test]
fn enforcing_events_are_enforce_deviations() {
    let pf = PlatformConfig {
        fault_policy: FaultPolicy::FailOpen,
        ..Default::default()
    };
    let (mut f, s, c) = fw(Some(0.5), true, pf, spec());
    let _ = f.check(&Command::twist(s, c, T0, tw(5.0, 0.0)), T0);
    // A fail-open fault of an enforcing firewall is real: Enforce.
    let cmd = Command::twist(s, c, T0 + MS, tw(0.1, 0.0));
    assert!(f.fault_verdict(&cmd, T0 + MS).is_passed());
    let devs = f.drain_deviations();
    assert_eq!(devs.len(), 2);
    assert!(devs.iter().any(|d| d.rule == rules::INTERNAL_FAULT));
    assert!(devs.iter().all(|d| d.mode == Mode::Enforce), "{devs:?}");
}

// --------------------------- finding 5: a spoofer cannot pin the robot

fn ramp_to_cruise(f: &mut Firewall, s: SourceId, c: ChannelId) -> u64 {
    let mut t = T0;
    for _ in 0..41 {
        t += 50 * MS;
        let _ = f.check(&Command::twist(s, c, t, tw(0.9, 0.0)), t);
    }
    let v = f.check(
        &Command::twist(s, c, t + 50 * MS, tw(0.9, 0.0)),
        t + 50 * MS,
    );
    assert!(out_twist(&v).linear.x > 0.89);
    t + 50 * MS
}

fn spoof_interleaved(
    f: &mut Firewall,
    s: SourceId,
    c: ChannelId,
    mut t: u64,
) -> (Vec<Verdict>, Vec<f64>) {
    let mut spoofs = vec![];
    let mut outs = vec![];
    for _ in 0..10 {
        let spoof = f.check(
            &Command::twist(SourceId::UNKNOWN, c, t + MS, tw(0.0, 0.0)),
            t + MS,
        );
        assert_eq!(spoof.reject_reason(), Some(RejectReason::UnknownSource));
        spoofs.push(spoof);
        t += 50 * MS;
        let v = f.check(&Command::twist(s, c, t, tw(0.9, 0.0)), t);
        outs.push(out_twist(&v).linear.x);
    }
    (spoofs, outs)
}

fn spoof_spec() -> ChannelSpec {
    ChannelSpec {
        max_linear_accel: Some(1.0),
        ..spec()
    }
}

/// Was: with the default platform, spoofed zero packets were substituted
/// and committed as the previous output, pinning a 0.9 m/s UGV near zero.
/// Now: the default drops foreign commands (nothing emitted), the legit
/// stream is unaffected, and every attempt is a Critical deviation.
#[test]
fn spoofer_cannot_pin_robot_with_default_platform() {
    let (mut f, s, c) = fw(Some(1.0), true, PlatformConfig::default(), spoof_spec());
    let t = ramp_to_cruise(&mut f, s, c);
    let _ = f.drain_deviations();
    let (spoofs, outs) = spoof_interleaved(&mut f, s, c, t);
    assert!(spoofs.iter().all(|v| v.output().is_none()), "{spoofs:?}");
    assert!(outs.iter().all(|x| *x > 0.89), "legit output: {outs:?}");
    let devs = f.drain_deviations();
    let foreign: Vec<_> = devs
        .iter()
        .filter(|d| d.rule == rules::REJECTED_UNKNOWN_SOURCE)
        .collect();
    assert_eq!(foreign.len(), 10, "every attempt recorded: {devs:?}");
    assert!(foreign
        .iter()
        .all(|d| d.severity == robodr_events::Severity::Critical && d.mode == Mode::Enforce));
}

/// Platform opt-in `Substitute`: the zero is emitted at most once per
/// interval (all attempts still recorded). The emitted zero is honestly the
/// channel's previous output, so the legit stream ramps up from it within
/// the acceleration limit — never a 0 → 0.9 m/s step.
#[test]
fn opt_in_foreign_substitute_is_bounded() {
    let pf = PlatformConfig {
        foreign_source_action: ForeignSourceAction::Substitute,
        ..Default::default()
    };
    let (mut f, s, c) = fw(Some(1.0), true, pf, spoof_spec());
    let t = ramp_to_cruise(&mut f, s, c);
    let _ = f.drain_deviations();
    let (spoofs, outs) = spoof_interleaved(&mut f, s, c, t);
    // 10 spoofs over ~500 ms, interval 1 s: exactly one zero emitted.
    let emitted = spoofs.iter().filter(|v| v.output().is_some()).count();
    assert_eq!(emitted, 1, "{spoofs:?}");
    assert!(spoofs[0].output().unwrap().motion.is_zero());
    // Ramp from the emitted zero at <= 1 m/s^2 (dt 49 ms, then 50 ms),
    // monotone, never above cruise.
    let mut prev = 0.0;
    for (k, x) in outs.iter().enumerate() {
        assert!(*x >= prev && *x - prev <= 0.05 + 1e-9, "{k}: {outs:?}");
        prev = *x;
    }
    // All ten are still recorded.
    let n = f
        .drain_deviations()
        .iter()
        .filter(|d| d.rule == rules::REJECTED_UNKNOWN_SOURCE)
        .count();
    assert_eq!(n, 10);
    // After the interval, another one is allowed.
    let later = t + 2_000 * MS;
    let v = f.check(
        &Command::twist(SourceId::UNKNOWN, c, later, tw(0.0, 0.0)),
        later,
    );
    assert!(v.output().is_some());
}

/// Interval 0 restores one substitute per foreign command.
#[test]
fn opt_in_foreign_substitute_unbounded_interval() {
    let pf = PlatformConfig {
        foreign_source_action: ForeignSourceAction::Substitute,
        foreign_substitute_min_interval_ns: 0,
        ..Default::default()
    };
    let (mut f, s, c) = fw(Some(1.0), true, pf, spoof_spec());
    let t = ramp_to_cruise(&mut f, s, c);
    let (spoofs, _) = spoof_interleaved(&mut f, s, c, t);
    assert!(spoofs.iter().all(|v| v.output().is_some()));
}

// ------------- finding 5b: rejected commands do not touch per-source state

fn rate_spec() -> ChannelSpec {
    ChannelSpec {
        rate_limit: Some(RateLimit {
            per_second: 10,
            burst: 2,
        }),
        ..spec()
    }
}

/// Was: a command rejected after the rate stage (NaN, wrong kind, stale,
/// future, over the hard limit) still consumed a token, so
/// garbage could starve the source's own valid commands. Now only accepted
/// commands consume credit.
#[test]
fn rejected_commands_do_not_consume_rate_credit() {
    let (mut f, s, c) = fw(Some(1.0), true, PlatformConfig::default(), rate_spec());
    let t = T0;
    let j = JointVelocities::from_slice(&[0.0; 6]).unwrap();
    let junk = [
        Command::twist(s, c, t, tw(f64::NAN, 0.0)),
        Command::joints(s, c, t, j),
        Command::twist(s, c, t - 900 * MS, tw(0.1, 0.0)),
        Command::twist(s, c, t + 10_000 * MS, tw(0.1, 0.0)),
        Command::twist(s, c, t, tw(100.0, 0.0)),
    ];
    for _ in 0..5 {
        for cmd in &junk {
            let v = f.check(cmd, t);
            assert!(v.is_rejected());
            assert_ne!(v.reject_reason(), Some(RejectReason::RateLimited), "{v:?}");
        }
    }
    // The full burst of 2 is still available at the same instant.
    assert!(f
        .check(&Command::twist(s, c, t, tw(0.1, 0.0)), t)
        .is_passed());
    assert!(f
        .check(&Command::twist(s, c, t + 1, tw(0.1, 0.0)), t)
        .is_passed());
    let v = f.check(&Command::twist(s, c, t + 2, tw(0.1, 0.0)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::RateLimited));
    // ... and the rate-limited one did not consume or reset anything:
    // 100 ms later exactly one token has refilled.
    let t2 = t + 100 * MS;
    assert!(f
        .check(&Command::twist(s, c, t2, tw(0.1, 0.0)), t2)
        .is_passed());
    let v = f.check(&Command::twist(s, c, t2 + 1, tw(0.1, 0.0)), t2);
    assert_eq!(v.reject_reason(), Some(RejectReason::RateLimited));
}

/// Was: an over-hard-limit command advanced the source's last stamp, so a
/// single garbage packet with a stamp near `now + max_future` made every
/// valid command of that source "out of order" until the clock caught up.
#[test]
fn rejected_commands_do_not_advance_last_stamp() {
    let (mut f, s, c) = fw(Some(1.0), true, PlatformConfig::default(), spec());
    let fut = T0 + ChannelSpec::default().max_future_ns;
    let v = f.check(&Command::twist(s, c, fut, tw(100.0, 0.0)), T0);
    assert_eq!(v.reject_reason(), Some(RejectReason::OverHardLimit));
    let v = f.check(&Command::twist(s, c, T0, tw(0.1, 0.0)), T0);
    assert!(v.is_passed(), "{v:?}");
    // Accepted stamps still order: a replay is out of order.
    let v = f.check(&Command::twist(s, c, T0, tw(0.1, 0.0)), T0 + MS);
    assert_eq!(v.reject_reason(), Some(RejectReason::OutOfOrder));
}

/// Per-source isolation: one authorised source exhausting its own rate
/// budget does not affect another authorised source on the same channel.
#[test]
fn rate_state_is_per_source() {
    let other = format!("{PREFIX}00000104");
    let sp = ChannelSpec {
        allowed_sources: vec![format!("{PREFIX}00000103"), other.clone()],
        ..rate_spec()
    };
    let (mut f, s, c) = fw(Some(1.0), true, PlatformConfig::default(), sp);
    let o = f.source_id(&other).unwrap();
    for k in 0..2 {
        assert!(f
            .check(&Command::twist(s, c, T0 + k, tw(0.1, 0.0)), T0)
            .is_passed());
    }
    let v = f.check(&Command::twist(s, c, T0 + 2, tw(0.1, 0.0)), T0);
    assert_eq!(v.reject_reason(), Some(RejectReason::RateLimited));
    assert!(f
        .check(&Command::twist(o, c, T0, tw(0.1, 0.0)), T0)
        .is_passed());
}
