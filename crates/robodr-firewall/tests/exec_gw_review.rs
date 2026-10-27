//! Regressions for the independent review of the executor / gateway
//! channels (findings F1-F10 of that review; the firewall side of F6 and
//! F10). Each test failed before its fix.

mod common;
use common::*;
use robodr_firewall::*;

const T: u64 = T0;

/// A humanoid joint channel whose `balance_critical` flag is set from JSON
/// (the way a site writes it).
fn hand_channel(balance_critical: Option<bool>) -> JFx {
    build_joint(humanoid(), true, 7, 7, |spec| {
        let mut v = serde_json::to_value(&*spec).expect("spec serialises");
        if let Some(b) = balance_critical {
            v["balance_critical"] = b.into();
        }
        *spec = serde_json::from_value(v).expect("balance_critical is a joint channel key");
    })
}

/// F6: the SDK releases a hand with `kp = kd = 0` on every motor
/// (`g1_dex3_example.cpp` `stopMotors`). On a humanoid the all-limp rule
/// refused that frame on every joint channel; a hand is not in the balance
/// loop, so a channel marked `balance_critical: false` may go limp.
#[test]
fn f6_hand_release_passes_on_a_non_balance_critical_channel() {
    let limp = |f: &JFx, stamp| {
        JointCommand::new(
            f.ctl,
            f.low,
            stamp,
            jframe(f.slots, f.active, |_| {
                MotorCmd::enabled(0.1, 0.0, 0.0, 0.0, 0.0)
            }),
        )
    };
    // Default (and explicit true): balance-critical, the limp frame is
    // refused as before.
    for flag in [None, Some(true)] {
        let mut f = hand_channel(flag);
        assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
        let v = f.fw.check_joint(&limp(&f, T + 10 * MS), T + 10 * MS);
        assert_eq!(
            v.reject_reason(),
            Some(RejectReason::JointLimpFrame),
            "{flag:?}"
        );
    }
    let mut f = hand_channel(Some(false));
    assert!(f.fw.check_joint(&f.nominal(T), T).is_passed());
    let v = f.fw.check_joint(&limp(&f, T + 10 * MS), T + 10 * MS);
    assert!(v.is_passed(), "hand release refused: {v:?}");
}

/// F10 (b): a request that commands no motion (a query) is checked for its
/// source and rate only; the twist state the next velocity is ramped from
/// stays as it was.
#[test]
fn f10b_check_access_leaves_the_motion_state() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.max_linear_speed = Some(2.0);
        b.max_linear_accel = Some(1.05);
        b.state_reset_after_ns = 5_000 * MS;
    });
    let mut t = T;
    for k in 1..=5 {
        t += 100 * MS;
        let v =
            f.fw.check(&twist_cmd(f.nav, f.base, t, vx(k as f64 / 10.0)), t);
        assert!(v.is_passed(), "ramp {k}: {v:?}");
    }
    t += 30 * MS;
    let zero = twist_cmd(f.nav, f.base, t, vx(0.0));
    assert!(f.fw.check_access(&zero, t));
    t += 70 * MS;
    let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.5)), t);
    assert!(v.is_passed(), "the query reset the twist state: {v:?}");
    // A foreign source is refused and recorded.
    t += 10 * MS;
    let foreign = twist_cmd(SourceId::UNKNOWN, f.base, t, vx(0.0));
    assert!(!f.fw.check_access(&foreign, t));
    let mut ev = Vec::new();
    f.fw.drain_events(|e| ev.push(e.rule));
    assert!(ev.iter().any(|r| r.contains("unknown_source")), "{ev:?}");
}

/// F10 (a): after `twist_at_rest` the next command is ramped from zero.
#[test]
fn f10a_twist_at_rest_ramps_from_zero() {
    let mut f = build(PlatformConfig::default(), true, |b, _| {
        b.max_linear_speed = Some(2.0);
        b.max_linear_accel = Some(1.05);
        b.state_reset_after_ns = 5_000 * MS;
    });
    let mut t = T;
    for k in 1..=5 {
        t += 100 * MS;
        assert!(f
            .fw
            .check(&twist_cmd(f.nav, f.base, t, vx(k as f64 / 10.0)), t)
            .is_passed());
    }
    f.fw.twist_at_rest(f.base, t + 1_000 * MS);
    t += 2_000 * MS;
    let v = f.fw.check(&twist_cmd(f.nav, f.base, t, vx(0.5)), t);
    let out = out_twist(&v);
    assert!(out.linear.x <= 0.105 + 1e-9, "{v:?}");
}
