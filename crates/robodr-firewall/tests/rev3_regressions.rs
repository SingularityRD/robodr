//! Regression tests for the rev3 safety review findings.
//!
//! Each of the first three tests is a port of a reviewer PoC (which passed
//! while the issue existed), rewritten to assert the fixed behaviour; the
//! others widen the coverage around the same fix.

use robodr_events::profile::{Envelope, Profile};
use robodr_events::Severity;
use robodr_firewall::*;
use std::collections::BTreeMap;

const PREFIX: &str = "0123456789abcdef01234567";
const MS: u64 = 1_000_000;
const T0: u64 = 1_000 * MS;
/// 1 m/s^2 over a 10 ms tick.
const ACCEL_STEP: f64 = 0.01;

fn fw(platform: PlatformConfig, spec: ChannelSpec) -> (Firewall, SourceId, ChannelId) {
    let mut p = Profile {
        model: "ugv".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(PREFIX.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            max_joint_speed: None,
            ..Default::default()
        },
    );
    let specs = BTreeMap::from([("/cmd_vel".to_string(), spec)]);
    let f = Firewall::new(Policy::compile(&p, platform, &specs).expect("compiles"));
    let s = f.source_id(&format!("{PREFIX}00000103")).unwrap();
    let c = f.channel_id("/cmd_vel").unwrap();
    (f, s, c)
}

fn spec() -> ChannelSpec {
    ChannelSpec {
        kind: ChannelKind::Twist,
        allowed_sources: vec![format!("{PREFIX}00000103")],
        max_angular_speed: Some(1.0),
        max_linear_accel: Some(1.0),
        max_angular_accel: Some(1.0),
        max_age_ns: 100 * MS,
        ..Default::default()
    }
}

fn holdlast(max_hold_ns: u64) -> PlatformConfig {
    PlatformConfig {
        fail_behaviour: FailBehaviour::HoldLast { max_hold_ns },
        ..Default::default()
    }
}

fn lx(v: &Verdict) -> f64 {
    match v.output().expect("emits").motion {
        Motion::Twist(t) => t.linear.x,
        Motion::Joints(_) => panic!(),
    }
}

fn tw(x: f64) -> Twist {
    Twist::new(Vec3::new(x, 0.0, 0.0), Vec3::ZERO)
}

fn sub_kind(v: &Verdict) -> SubstituteKind {
    match v {
        Verdict::Rejected {
            substitute: Some(s),
            ..
        } => s.kind,
        _ => panic!("{v:?}"),
    }
}

/// Ramp to ~0.9 m/s within the accel limit; returns last `now`.
fn ramp(f: &mut Firewall, s: SourceId, c: ChannelId) -> u64 {
    let mut t = T0;
    for _ in 0..120 {
        t += 10 * MS;
        let v = f.check(&Command::twist(s, c, t, tw(0.9)), t);
        assert!(!v.is_rejected());
    }
    assert!(
        (lx(&f.check(&Command::twist(s, c, t + 10 * MS, tw(0.9)), t + 10 * MS)) - 0.9).abs() < 1e-9
    );
    t + 10 * MS
}

// --------------------------------------------------------------------- F1

/// Was: after a zero substitute, a rejected same-direction command made
/// `HoldLast` re-emit the last *accepted* 0.9 m/s — a 0 -> 0.9 step that
/// skipped the acceleration limit. Now the hold never exceeds what was last
/// emitted, so the output stays at zero.
#[test]
fn holdlast_never_reinstates_motion_after_zero_substitute() {
    let (mut f, s, c) = fw(holdlast(1_000 * MS), spec());
    let mut t = ramp(&mut f, s, c);
    // Stale slow-down -> zero substitute is emitted (robot told to stop).
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.3)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::Stale));
    assert_eq!(lx(&v), 0.0);
    // Another stale, same-direction command: still zero, never a step up.
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.9)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::Stale));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
    assert!(
        lx(&v) <= ACCEL_STEP,
        "rejected command stepped 0 -> {}",
        lx(&v)
    );
    // The next accepted command ramps up from zero within the limit.
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t, tw(0.9)), t);
    assert!(v.is_limited());
    assert!(lx(&v) <= ACCEL_STEP + 1e-12);
}

/// A foreign zero substitute also resets what may be held.
#[test]
fn holdlast_after_foreign_zero_substitute_is_zero() {
    let pf = PlatformConfig {
        foreign_source_action: ForeignSourceAction::Substitute,
        ..holdlast(1_000 * MS)
    };
    let (mut f, s, c) = fw(pf, spec());
    let mut t = ramp(&mut f, s, c);
    t += 10 * MS;
    let v = f.check(&Command::twist(SourceId::UNKNOWN, c, t, tw(0.0)), t);
    assert_eq!(lx(&v), 0.0);
    t += 10 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.9)), t);
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
}

/// The hold is still granted in the case it exists for: last emitted ==
/// last accepted, a rejected command asking for at least as much.
#[test]
fn holdlast_still_holds_when_nothing_was_lowered() {
    let (mut f, s, c) = fw(holdlast(1_000 * MS), spec());
    let mut t = ramp(&mut f, s, c);
    for _ in 0..5 {
        t += 10 * MS;
        let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.95)), t);
        assert_eq!(sub_kind(&v), SubstituteKind::HoldLast);
        assert!((lx(&v) - 0.9).abs() < 1e-9);
    }
}

/// A hold is not granted when the last emission is older than the channel's
/// reset gap (the platform may have stopped by itself): zero instead.
#[test]
fn holdlast_needs_a_recent_emission() {
    let sp = ChannelSpec {
        state_reset_after_ns: 50 * MS,
        ..spec()
    };
    let (mut f, s, c) = fw(holdlast(1_000 * MS), sp);
    let mut t = ramp(&mut f, s, c);
    t += 60 * MS;
    let v = f.check(&Command::twist(s, c, t - 150 * MS, tw(0.95)), t);
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
}

/// Randomized: every emitted output on a HoldLast channel (accepted or
/// substitute) either only decelerates from the previous emission or
/// changes by at most the acceleration allowance.
#[test]
fn holdlast_emitted_stream_never_steps_up_past_accel_limit() {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    for _ in 0..50 {
        let (mut f, s, c) = fw(holdlast(300 * MS), spec());
        let mut t = T0;
        // (last emitted value, when); `None`: nothing emitted recently, so
        // the firewall assumes rest.
        let mut prev: Option<(f64, u64)> = None;
        let mut last_stamp = T0;
        for _ in 0..400 {
            t += 10 * MS;
            let x = (next() % 2_000) as f64 / 1_000.0 - 1.0;
            let stamp = match next() % 6 {
                0 => t - 200 * MS,    // stale
                1 => last_stamp,      // out of order
                2 => t + 10_000 * MS, // future
                _ => t,               // fresh
            };
            let src = if next() % 10 == 0 {
                SourceId::UNKNOWN
            } else {
                s
            };
            let v = f.check(&Command::twist(src, c, stamp, tw(x)), t);
            if v.is_passed() || v.is_limited() {
                last_stamp = stamp;
            }
            let Some(out) = v.output() else { continue };
            let Motion::Twist(o) = out.motion else {
                panic!()
            };
            let o = o.linear.x;
            // Defaults: reset after 500 ms, dt capped at 100 ms.
            let (p, dt) = match prev {
                Some((p, at)) if t - at <= 500 * MS => (p, (t - at).min(100 * MS)),
                _ => (0.0, 100 * MS),
            };
            let allowance = 1.0 * dt as f64 * 1e-9;
            let decel = o == 0.0 || (o * p > 0.0 && o.abs() <= p.abs());
            assert!(
                decel || (o - p).abs() <= allowance * (1.0 + 1e-9),
                "{p} -> {o} ({v:?})"
            );
            prev = Some((o, t));
        }
    }
}

// --------------------------------------------------------------------- F2

/// Was: during a gateway clock regression the hold age was
/// `now.saturating_sub(at) = 0`, so HoldLast never expired. Now a clock
/// regression never earns a hold: zero from the first regressed tick.
#[test]
fn holdlast_not_granted_under_clock_regression() {
    let (mut f, s, c) = fw(holdlast(100 * MS), spec());
    let t_ok = ramp(&mut f, s, c);
    let mut t = t_ok - 1_000 * MS;
    for _ in 0..95 {
        t += 10 * MS;
        let v = f.check(&Command::twist(s, c, t, tw(0.9)), t);
        assert_eq!(v.reject_reason(), Some(RejectReason::ClockRegression));
        assert_eq!(sub_kind(&v), SubstituteKind::Zero);
        assert_eq!(lx(&v), 0.0);
    }
    // Once the clock is past the last good reading, the stream resumes
    // from the emitted zero (last emitted at t_ok - 50 ms), within the
    // acceleration limit: 1 m/s^2 * 60 ms.
    let t = t_ok + 10 * MS;
    let v = f.check(&Command::twist(s, c, t, tw(0.9)), t);
    assert!(!v.is_rejected());
    assert!(lx(&v) <= 0.06 + 1e-9, "{v:?}");
}

/// A small regression (still after the last acceptance) is no exception.
#[test]
fn holdlast_not_granted_under_small_clock_regression() {
    let (mut f, s, c) = fw(holdlast(1_000 * MS), spec());
    let t_ok = ramp(&mut f, s, c);
    let v = f.check(&Command::twist(s, c, t_ok - 1, tw(0.95)), t_ok - 1);
    assert_eq!(v.reject_reason(), Some(RejectReason::ClockRegression));
    assert_eq!(sub_kind(&v), SubstituteKind::Zero);
}

// --------------------------------------------------------------------- F3

/// Was: the buffer dropped the newest event when full, so a spoofer flood
/// evicted an authorised source's Critical event. Now the flood coalesces
/// and is capped, and the Critical is kept.
#[test]
fn foreign_flood_does_not_evict_critical_event_of_authorised_source() {
    let (mut f, s, c) = fw(PlatformConfig::default(), spec());
    let cap = f.events().capacity();
    let mut t = T0;
    for _ in 0..cap {
        t += 1;
        let v = f.check(&Command::twist(SourceId::UNKNOWN, c, t, tw(0.1)), t);
        assert!(v.is_rejected());
    }
    t += MS;
    let v = f.check(&Command::twist(s, c, t, tw(100.0)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::OverHardLimit));
    let devs = f.drain_deviations();
    let crit = devs
        .iter()
        .find(|d| d.rule == rules::REJECTED_OVER_HARD_LIMIT)
        .expect("authorised Critical kept");
    assert_eq!(crit.severity, Severity::Critical);
    let flood = devs
        .iter()
        .find(|d| d.rule == rules::REJECTED_UNKNOWN_SOURCE)
        .expect("flood recorded");
    assert!(flood.detail.contains(&format!(" x{cap} ")), "{flood:?}");
    assert!(!devs.iter().any(|d| d.rule == rules::EVENTS_DROPPED));
}

/// A flood of *distinct* foreign events (unknown channels, so no
/// coalescing) occupies at most half the buffer and never evicts an
/// authorised Critical, before or after it arrives. Lost events are
/// reported with the severity of the worst one lost.
#[test]
fn distinct_foreign_flood_is_capped_and_reported() {
    let pf = PlatformConfig {
        event_capacity: 16,
        ..Default::default()
    };
    let (mut f, s, c) = fw(pf, spec());
    let mut t = T0 + MS;
    // Authorised Critical first.
    let v = f.check(&Command::twist(s, c, t, tw(f64::NAN)), t);
    assert_eq!(v.reject_reason(), Some(RejectReason::NonFinite));
    for k in 0..2_000u16 {
        t += 1;
        let ch = ChannelId(100 + k);
        let v = f.check(&Command::twist(SourceId::UNKNOWN, ch, t, tw(0.1)), t);
        assert!(v.is_rejected());
        if k == 1_000 {
            // Authorised Critical in the middle of the flood.
            let v = f.check(&Command::twist(s, c, t, tw(100.0)), t);
            assert_eq!(v.reject_reason(), Some(RejectReason::OverHardLimit));
        }
    }
    let ev = f.events().as_slice();
    assert!(ev.iter().filter(|e| !e.authorised).count() <= 8);
    for rule in [rules::REJECTED_NON_FINITE, rules::REJECTED_OVER_HARD_LIMIT] {
        assert!(
            ev.iter().any(|e| e.rule == rule && e.authorised),
            "{rule} evicted"
        );
    }
    let devs = f.drain_deviations();
    let dropped = devs
        .iter()
        .find(|d| d.rule == rules::EVENTS_DROPPED)
        .expect("drops reported");
    assert_eq!(dropped.severity, Severity::High);
}
