//! Regression tests for the wave-2 safety review findings against the
//! responder. Ported from the reviewer's PoCs
//! (`review-safety/repo/crates/robodr-responder/tests/review_poc.rs`), which
//! passed while the issues existed; these assert the fixed behaviour.

use robodr_events::{Deviation, Mode, Severity};
use robodr_responder::*;

fn ctx() -> OperationalContext {
    OperationalContext {
        platform: PlatformFamily::Ugv,
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: true,
    }
}

fn pol() -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    p.oem_validated = true;
    p
}

/// Finding 1 [HIGH]: `Deviation::mode` was ignored, so an observe-mode
/// deviation got an executable motion-affecting plan. Fixed: Record only,
/// `observe_only`, with the would-have plan attached.
#[test]
fn observe_mode_deviation_is_never_executed() {
    let d = Deviation::new("robot.firewall.limited_speed", Severity::High, "x")
        .with_mode(Mode::Observe);
    assert!(d.is_observe_only());
    let state = SafetyState::MovingFast;
    let plan = plan_stateless(&pol(), &d, "src", state, &ctx());
    assert!(plan.observe_only);
    assert_eq!(plan.actions, vec![ResponseAction::Record]);
    assert_eq!(plan.max_step, Step::Record);
    assert!(!plan.requires_human_approval);
    let w = plan.would_have.as_ref().expect("would_have filled");
    assert!(w
        .actions
        .iter()
        .any(|a| matches!(a, ResponseAction::LimitMotion { .. })));
    assert!(plan
        .rationale
        .contains(|r| *r == Reason::ObserveModeDeviation));
    assert_eq!(
        check_invariants_for_deviation(&plan, &d, state, &ctx()),
        Ok(())
    );

    // Same through the stateful responder.
    let mut r = Responder::new(pol()).unwrap();
    let p = r.plan(&d, "src", state, &ctx(), 0);
    assert!(p.observe_only);
    assert_eq!(p.actions, vec![ResponseAction::Record]);

    // The enforce-mode plan, re-checked against the observe-mode deviation,
    // is a violation.
    let enforce_plan = plan_stateless(
        &pol(),
        &d.clone().with_mode(Mode::Enforce),
        "src",
        state,
        &ctx(),
    );
    assert_eq!(
        check_invariants_for_deviation(&enforce_plan, &d, state, &ctx()),
        Err(Violation::ObserveOnlyDeviationActed)
    );
}

/// Finding 2 [MEDIUM]: the robot-wide limiter counted approval-pending plans
/// as issued, so a Critical decoy every 5 s from fresh source ids muted every
/// real High deviation's LimitMotion from another source (20/20). Fixed:
/// rate limiting is per (source, rule) and counts only auto-executable plans.
#[test]
fn decoys_cannot_suppress_other_sources_responses() {
    let mut r = Responder::new(pol()).unwrap();
    let crit = Deviation::new(
        "robot.ros2.unknown_participant",
        Severity::Critical,
        "decoy",
    );
    let high = Deviation::new("robot.firewall.limited_speed", Severity::High, "real");
    let mut suppressed = 0;
    for k in 0..20u64 {
        let t = k * 5_000;
        let p = r.plan(
            &crit,
            &format!("decoy-{k}"),
            SafetyState::MovingFast,
            &ctx(),
            t,
        );
        assert!(p.requires_human_approval);
        let q = r.plan(
            &high,
            "real-attacker",
            SafetyState::MovingFast,
            &ctx(),
            t + 1_000,
        );
        if q.suppressed {
            suppressed += 1;
        }
        assert!(!q.requires_human_approval, "k={k}: {q:?}");
        assert!(
            q.actions
                .iter()
                .any(|a| matches!(a, ResponseAction::LimitMotion { .. })),
            "k={k}: {q:?}"
        );
    }
    assert_eq!(suppressed, 0, "no real response suppressed");

    // Tighter decoy cadence (every 100 ms) and a fresh real source each
    // round: still never suppressed, and the source-specific Restrict is
    // always present.
    let mut r = Responder::new(pol()).unwrap();
    for k in 0..25u64 {
        let t = k * 100;
        r.plan(
            &crit,
            &format!("decoy-{k}"),
            SafetyState::MovingFast,
            &ctx(),
            t,
        );
        let q = r.plan(
            &high,
            &format!("real-{k}"),
            SafetyState::MovingFast,
            &ctx(),
            t + 1,
        );
        assert!(!q.suppressed, "k={k}");
        assert!(q
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::Restrict { .. })));
    }
}
