//! W2-5 review PoC: global budget exhaustion folds an unrelated Critical.
use robodr_agentd::gateway_feed::*;
use robodr_events::{Mode, Severity};

fn line(rule: &str, sev: Severity, ch: &str) -> GatewayLine {
    GatewayLine {
        format: "robodr-gateway-finding/v1".into(),
        rule: rule.into(),
        severity: sev,
        detail: "d".into(),
        mode: Mode::Enforce,
        channel: Some(ch.into()),
        count: 1,
    }
}

#[test]
fn global_budget_flood_delays_critical() {
    use robodr_firewall::rules as fw;
    let mut l = GatewayLimiter::new(0);
    let noisy = [
        fw::LIMITED_SPEED, fw::REJECTED_RATE_LIMITED, fw::REJECTED_STALE, fw::REJECTED_UNKNOWN_CHANNEL,
        fw::REJECTED_KIND_MISMATCH, fw::REJECTED_OUT_OF_ORDER, fw::LIMITED_ACCELERATION,
        fw::LIMITED_JERK, fw::JOINT_RATE_VIOLATION, fw::REJECTED_FUTURE_TIMESTAMP,
    ];
    // 10 rules x 20 burst = the feed's 200 burst, each rule within its own budget.
    let mut t = 0u64;
    for r in noisy {
        let sev = severity_range(r).unwrap().0;
        for i in 0..20 {
            assert!(matches!(l.admit(&line(r, sev, &format!("/c{i}")), t), Admitted::Report { .. }));
        }
    }
    // Keep the feed at ~600/min with the noisy rules (each 60/min) ...
    t += 100;
    let crit = line(fw::REJECTED_OVER_HARD_LIMIT, Severity::Critical, "/arm/cmd");
    let r = l.admit(&crit, t);
    println!("first-ever Critical over_hard_limit after the flood: {r:?}");
    assert_eq!(r, Admitted::Folded);
    assert!(l.drain(t + 59_000, false).is_empty(), "nothing for 59 s");
    let agg = l.drain(t + 60_000, false);
    println!("aggregate at +60 s: {agg:?}");
    assert_eq!(agg.len(), 1);
    assert_eq!(agg[0].channel, None);
}
