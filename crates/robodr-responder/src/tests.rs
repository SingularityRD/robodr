//! Crate tests: matrix, invariants (exhaustive + randomized), escalation and
//! hysteresis timelines, policy validation, platform differences.

use robodr_events::{Deviation, Mode, Severity};

use crate::actions::{for_action, spec_for};
use crate::escalation::{
    MAX_MOTION_GUARD_MS, MAX_REISSUE_KEYS, MAX_SOURCES, MAX_SOURCE_KEY_LEN, OVERFLOW_SOURCE,
};
use crate::policy::{MAX_RULE_OVERRIDES, SCHEMA};
use crate::*;

const RULE_A: &str = "robot.ros2.unknown_participant";
const RULE_B: &str = "robot.motion.envelope_exceeded";
const SEVS: [Severity; 4] = [
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

/// Tiny deterministic PRNG (xorshift64*), std only.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

/// The statically stable morphology most tests declare for a family (the
/// conservative default leaves it unspecified, which is fall-prone).
fn stable(platform: PlatformFamily) -> Morphology {
    match platform {
        PlatformFamily::Ugv | PlatformFamily::Amr => Morphology::WheeledMobile,
        PlatformFamily::Drone => Morphology::Aerial,
        PlatformFamily::Arm => Morphology::Arm,
        PlatformFamily::Other => Morphology::Other,
    }
}

fn enforced(platform: PlatformFamily) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(platform);
    p.oem_validated = true;
    p.model = "test-model".into();
    p.morphology = stable(platform);
    p
}

fn ctx(platform: PlatformFamily) -> OperationalContext {
    OperationalContext {
        platform,
        morphology: stable(platform),
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: true,
    }
}

fn dev(sev: Severity) -> Deviation {
    Deviation::new(RULE_A, sev, "test")
}

fn has_terminate(p: &ResponsePlan) -> bool {
    p.actions.iter().any(|a| {
        matches!(
            a,
            ResponseAction::Restrict {
                terminate_process: true,
                ..
            }
        )
    })
}

// ---------------------------------------------------------------- ladder ---

#[test]
fn step_order_and_raise() {
    assert!(Step::Record < Step::Restrict);
    assert!(Step::SafePause < Step::RequestSafeState);
    assert_eq!(Step::Record.raised(1), Step::Restrict);
    assert_eq!(Step::SafePause.raised(9), Step::RequestSafeState);
    assert_eq!(Step::RequestSafeState.raised(255), Step::RequestSafeState);
    assert_eq!(Step::Record.rung(), 1);
    assert_eq!(Step::RequestSafeState.rung(), 5);
    assert!(!Step::Restrict.is_motion_affecting());
    assert!(Step::LimitMotion.is_motion_affecting());
}

// ---------------------------------------------------------------- matrix ---

#[test]
fn default_matrix_full_table() {
    use Step::*;
    let expected: [(SafetyState, [Step; 4]); 7] = [
        (SafetyState::Idle, [Record, Restrict, Restrict, SafePause]),
        (
            SafetyState::MovingSlow,
            [Record, Record, LimitMotion, RequestSafeState],
        ),
        (
            SafetyState::MovingFast,
            [Record, Record, LimitMotion, RequestSafeState],
        ),
        (
            SafetyState::CollaborativeHumanNearby,
            [Record, LimitMotion, SafePause, RequestSafeState],
        ),
        (SafetyState::EStopActive, [Record; 4]),
        (SafetyState::SafeStateActive, [Record; 4]),
        (
            SafetyState::Unknown,
            [Record, Record, Restrict, RequestSafeState],
        ),
    ];
    for platform in PlatformFamily::ALL {
        let p = enforced(platform);
        p.validate().unwrap();
        let c = ctx(platform);
        for (state, row) in expected {
            for (sev, want) in SEVS.into_iter().zip(row) {
                let plan = plan_stateless(&p, &dev(sev), "src", state, &c);
                assert_eq!(plan.max_step, want, "{platform:?} {state:?} {sev:?}");
                // Cumulative ladder: every step up to max is present.
                let steps = plan.steps();
                let expect_steps: Vec<Step> =
                    Step::ALL.into_iter().filter(|s| *s <= want).collect();
                assert_eq!(steps, expect_steps);
                // Auto ceiling is LimitMotion; Unknown gates motion steps.
                let need = want > Step::LimitMotion
                    || (state == SafetyState::Unknown && want.is_motion_affecting());
                assert_eq!(plan.requires_human_approval, need, "{state:?} {sev:?}");
                assert!(!plan.observe_only);
                assert!(!plan.rationale_text().is_empty());
            }
        }
    }
}

#[test]
fn demo_critical_on_moving_ugv_requests_safe_state() {
    let p = enforced(PlatformFamily::Ugv);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "g",
        SafetyState::MovingFast,
        &ctx(PlatformFamily::Ugv),
    );
    assert_eq!(
        plan.actions.last(),
        Some(&ResponseAction::RequestSafeState {
            behaviour: SafeBehaviour::ControlledStop
        })
    );
    assert!(plan.requires_human_approval);
    assert_eq!(plan.actions[0], ResponseAction::Record);
}

// ------------------------------------------------------------ invariants ---

/// Independent re-statement of the invariants (not via check_invariants).
fn assert_invariants(
    plan: &ResponsePlan,
    policy: &ResponsePolicy,
    state: SafetyState,
    c: &OperationalContext,
) {
    let tag = format!("{state:?} {c:?} {plan:?}");
    assert_eq!(check_invariants(plan, state, c), Ok(()), "{tag}");
    assert_eq!(plan.actions.first(), Some(&ResponseAction::Record), "{tag}");
    let only_record = plan.actions.iter().all(|a| *a == ResponseAction::Record);
    if state.safety_system_engaged() {
        assert!(only_record, "engaged: {tag}");
    }
    if !c.profile_locked || !policy.oem_validated {
        assert!(plan.observe_only && only_record, "observe: {tag}");
        assert!(plan.would_have.is_some(), "{tag}");
    }
    if c.platform != policy.platform {
        assert!(only_record || plan.observe_only, "{tag}");
    }
    let motion = plan.actions.iter().any(|a| a.step().is_motion_affecting());
    if motion
        && (state == SafetyState::Unknown || c.control.human_in_command() || c.phase.is_transient())
    {
        assert!(plan.requires_human_approval, "{tag}");
    }
    if !plan.requires_human_approval {
        assert!(
            plan.max_step <= policy.auto_max_step.max(Step::Record),
            "{tag}"
        );
    }
    if has_terminate(plan) {
        assert_eq!(state, SafetyState::Idle, "{tag}");
        assert!(policy.allow_terminate_when_idle);
        assert!(!policy.morphology.needs_active_balance(), "{tag}");
    }
    if policy.morphology.falls_when_de_energised() && !plan.advisory.is_empty() {
        assert!(plan.requires_human_approval, "{tag}");
    }
    for a in plan
        .actions
        .iter()
        .chain(plan.would_have.iter().flat_map(|w| w.actions.iter()))
    {
        match a {
            ResponseAction::SafePause { behaviour }
            | ResponseAction::RequestSafeState { behaviour } => {
                assert!(behaviour.allowed_for(c.platform), "{tag}");
                if c.platform == PlatformFamily::Drone {
                    assert!(matches!(
                        behaviour,
                        SafeBehaviour::Hold
                            | SafeBehaviour::ReturnToLaunch
                            | SafeBehaviour::PlatformDefined
                    ));
                }
            }
            ResponseAction::LimitMotion { factor } => {
                assert!(factor.is_finite() && *factor > 0.0 && *factor <= 1.0)
            }
            _ => {}
        }
    }
}

fn all_contexts() -> Vec<OperationalContext> {
    let mut v = Vec::new();
    for platform in PlatformFamily::ALL {
        for phase in MissionPhase::ALL {
            for connectivity in Connectivity::ALL {
                for control in ControlMode::ALL {
                    for operator_present in [false, true] {
                        for profile_locked in [false, true] {
                            v.push(OperationalContext {
                                platform,
                                morphology: stable(platform),
                                phase,
                                connectivity,
                                control,
                                operator_present,
                                profile_locked,
                            });
                        }
                    }
                }
            }
        }
    }
    v
}

#[test]
fn invariants_exhaustive_over_enum_combinations() {
    let contexts = all_contexts();
    let mut n = 0;
    for policy_platform in PlatformFamily::ALL {
        for validated in [false, true] {
            let mut p = enforced(policy_platform);
            p.oem_validated = validated;
            p.allow_terminate_when_idle = true;
            p.default_restrict = RestrictTarget::ALL.to_vec();
            for c in &contexts {
                for state in SafetyState::ALL {
                    for sev in SEVS {
                        let plan = plan_stateless(&p, &dev(sev), "s", state, c);
                        assert_invariants(&plan, &p, state, c);
                        let od = dev(sev).with_mode(Mode::Observe);
                        let o = plan_stateless(&p, &od, "s", state, c);
                        assert_invariants(&o, &p, state, c);
                        assert_eq!(check_invariants_for_deviation(&o, &od, state, c), Ok(()));
                        assert!(o.observe_only && o.max_step == Step::Record);
                        n += 1;
                    }
                }
            }
        }
    }
    assert!(n > 100_000);
}

fn random_policy(r: &mut Rng) -> ResponsePolicy {
    let platform = r.pick(&PlatformFamily::ALL);
    let mut p = ResponsePolicy::conservative_default(platform);
    p.oem_validated = r.below(4) != 0;
    let row = |r: &mut Rng| SeverityRow {
        low: r.pick(&Step::ALL),
        medium: r.pick(&Step::ALL),
        high: r.pick(&Step::ALL),
        critical: r.pick(&Step::ALL),
    };
    p.matrix.idle = row(r);
    p.matrix.moving_slow = row(r);
    p.matrix.moving_fast = row(r);
    p.matrix.collaborative_human_nearby = row(r);
    p.matrix.unknown = row(r);
    p.auto_max_step = r.pick(&Step::ALL);
    p.limit_motion_factor = (r.below(100) + 1) as f64 / 100.0;
    let allowed: Vec<SafeBehaviour> = SafeBehaviour::ALL
        .into_iter()
        .filter(|b| b.allowed_for(platform))
        .collect();
    p.safe_pause = r.pick(&allowed);
    p.safe_state = r.pick(&allowed);
    p.morphology = r.pick(&Morphology::ALL);
    if p.morphology.is_unspecified() && (p.oem_validated || platform == PlatformFamily::Other) {
        p.morphology = stable(platform);
    }
    p.allow_terminate_when_idle = r.bool() && !p.morphology.needs_active_balance();
    p.min_motion_factor = (r.below(46) + 5) as f64 / 100.0;
    if p.morphology.needs_active_balance() {
        p.limit_motion_factor = p.limit_motion_factor.max(p.min_motion_factor);
    }
    if p.morphology.falls_when_de_energised() {
        p.fall_safe_restrict = match r.below(4) {
            0 => vec![RestrictTarget::Network],
            1 => vec![RestrictTarget::Participant, RestrictTarget::Network],
            _ => Vec::new(),
        };
    }
    p.default_restrict = vec![r.pick(&RestrictTarget::ALL)];
    if r.bool() {
        let a = r.pick(&Step::ALL);
        let b = r.pick(&Step::ALL);
        p.rule_overrides.push(RuleOverride {
            rule: RULE_A.into(),
            min_step: a.min(b),
            max_step: a.max(b),
            restrict: Some(vec![RestrictTarget::Process, RestrictTarget::Network]),
        });
    }
    p.escalation.threshold = 2 + r.below(4) as u32;
    p.escalation.max_escalation_steps = r.below(3) as u8;
    p.escalation.ceiling = r.pick(&Step::ALL);
    p.escalation.window_ms = 1_000 + r.below(10_000) as u64;
    p.escalation.quiet_period_ms = p.escalation.window_ms * (1 + r.below(5) as u64);
    p.escalation.min_reissue_interval_ms = r.below(p.escalation.quiet_period_ms as usize) as u64;
    p.validate().expect("random policy is valid");
    p
}

#[test]
fn invariants_randomized_with_escalation_state() {
    let mut r = Rng(0x5EED_1234_ABCD_0001);
    let contexts = all_contexts();
    for _ in 0..300 {
        let policy = random_policy(&mut r);
        let mut resp = Responder::new(policy.clone()).unwrap();
        let mut now = 0u64;
        for _ in 0..200 {
            // Mostly forward, occasionally backwards (clock step), sometimes big jumps.
            now = match r.below(10) {
                0 => now.saturating_sub(r.below(5_000) as u64),
                1 => now + r.below(1_000_000) as u64,
                _ => now + r.below(2_000) as u64,
            };
            let state = r.pick(&SafetyState::ALL);
            let mut c = contexts[r.below(contexts.len())];
            if r.below(3) == 0 {
                c.platform = policy.platform; // bias towards matching platform
            }
            if r.below(4) != 0 {
                c.morphology = policy.morphology; // and morphology
            }
            let rule = if r.bool() { RULE_A } else { RULE_B };
            let mut d = Deviation::new(rule, r.pick(&SEVS), "x");
            if r.below(5) == 0 {
                d = d.with_mode(Mode::Observe);
            }
            let src = ["a", "b", "c"][r.below(3)];
            let plan = resp.plan(&d, src, state, &c, now);
            assert_invariants(&plan, &policy, state, &c);
            assert_eq!(check_invariants_for_deviation(&plan, &d, state, &c), Ok(()));
            if d.is_observe_only() {
                assert!(plan.observe_only && plan.max_step == Step::Record);
            }
            if r.below(50) == 0 {
                resp.acknowledge(if r.bool() { Some(src) } else { None }, now);
            }
        }
    }
}

#[test]
fn check_invariants_rejects_bad_plans() {
    let c = ctx(PlatformFamily::Drone);
    let p = enforced(PlatformFamily::Drone);
    let good = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    assert_eq!(check_invariants(&good, SafetyState::MovingFast, &c), Ok(()));

    let mut bad = good.clone();
    bad.actions.remove(0);
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::NotStartingWithRecord)
    );

    assert_eq!(
        check_invariants(&good, SafetyState::EStopActive, &c),
        Err(Violation::ActionWhileSafetySystemEngaged)
    );

    let mut bad = good.clone();
    bad.requires_human_approval = false;
    assert_eq!(
        check_invariants(&bad, SafetyState::Unknown, &c),
        Err(Violation::MotionWithoutApproval)
    );

    let mut bad = good.clone();
    bad.actions.push(ResponseAction::Record);
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::OutOfOrder)
    );

    let mut bad = good.clone();
    *bad.actions.last_mut().unwrap() = ResponseAction::RequestSafeState {
        behaviour: SafeBehaviour::ControlledStop,
    };
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::SafeBehaviourInvalidForPlatform)
    );

    let mut bad = good.clone();
    for a in bad.actions.iter_mut() {
        if let ResponseAction::LimitMotion { factor } = a {
            *factor = f64::NAN;
        }
    }
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::BadLimitFactor)
    );

    let mut bad = good.clone();
    bad.actions.insert(
        1,
        ResponseAction::Restrict {
            target: RestrictTarget::Process,
            terminate_process: true,
        },
    );
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::TerminateWhileNotIdle)
    );

    let mut bad = good.clone();
    bad.observe_only = true;
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::ObserveModeNotRecordOnly)
    );

    let mut bad = good;
    bad.max_step = Step::Record;
    assert_eq!(
        check_invariants(&bad, SafetyState::MovingFast, &c),
        Err(Violation::MaxStepMismatch)
    );
}

#[test]
fn unvalidated_policy_bypassing_validate_is_still_safe() {
    // Construct a policy that skips validate() and tries to exceed invariants.
    let mut p = enforced(PlatformFamily::Drone);
    p.matrix.estop_active = SeverityRow::uniform(Step::RequestSafeState);
    p.safe_pause = SafeBehaviour::ControlledStop; // "stop" a drone in flight
    p.safe_state = SafeBehaviour::ProtectiveStopCategory2;
    p.limit_motion_factor = f64::INFINITY;
    assert!(p.validate().is_err());
    let c = ctx(PlatformFamily::Drone);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::EStopActive,
        &c,
    );
    assert_eq!(plan.actions, vec![ResponseAction::Record]);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    assert_eq!(check_invariants(&plan, SafetyState::MovingFast, &c), Ok(()));
    assert!(plan.requires_human_approval);
    assert!(plan.actions.iter().all(|a| !matches!(
        a,
        ResponseAction::SafePause { .. }
            | ResponseAction::RequestSafeState { .. }
            | ResponseAction::LimitMotion { .. }
    )));
    assert!(plan
        .rationale
        .contains(|r| matches!(r, Reason::InvalidSafeBehaviour { .. })));
    assert!(plan
        .rationale
        .contains(|r| matches!(r, Reason::InvalidLimitFactor)));
}

#[test]
fn safety_system_engaged_is_record_only_even_with_escalation() {
    let mut p = enforced(PlatformFamily::Arm);
    p.escalation.max_escalation_steps = 2;
    p.escalation.ceiling = Step::RequestSafeState;
    let mut r = Responder::new(p).unwrap();
    let c = ctx(PlatformFamily::Arm);
    for state in [SafetyState::EStopActive, SafetyState::SafeStateActive] {
        for i in 0..50 {
            let plan = r.plan(&dev(Severity::Critical), "s", state, &c, i * 10);
            assert_eq!(plan.actions, vec![ResponseAction::Record]);
            assert!(plan
                .rationale
                .contains(|x| *x == Reason::SafetySystemHasAuthority));
        }
    }
}

#[test]
fn unknown_state_needs_approval_for_motion_but_not_restrict() {
    let p = enforced(PlatformFamily::Ugv);
    let c = ctx(PlatformFamily::Ugv);
    let high = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::Unknown, &c);
    assert_eq!(high.max_step, Step::Restrict);
    assert!(!high.requires_human_approval);
    let crit = plan_stateless(&p, &dev(Severity::Critical), "s", SafetyState::Unknown, &c);
    assert!(crit.requires_human_approval);
    assert!(crit
        .rationale
        .contains(|r| *r == Reason::UnknownSafetyState));
}

#[test]
fn observe_mode_records_with_would_have() {
    let p = enforced(PlatformFamily::Ugv);
    let mut c = ctx(PlatformFamily::Ugv);
    c.profile_locked = false;
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    assert!(plan.observe_only);
    assert_eq!(plan.actions, vec![ResponseAction::Record]);
    assert!(!plan.requires_human_approval);
    let w = plan.would_have.as_ref().unwrap();
    assert_eq!(w.max_step, Step::RequestSafeState);
    assert!(!w.observe_only);
    assert!(plan
        .rationale
        .contains(|r| *r == Reason::ObserveModeProfileUnlocked));

    // Default (not OEM-validated) policy: observe even with a locked profile.
    let d = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    let plan = plan_stateless(
        &d,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &ctx(PlatformFamily::Ugv),
    );
    assert!(plan.observe_only);
    assert!(plan
        .rationale
        .contains(|r| *r == Reason::ObserveModePolicyNotValidated));
}

#[test]
fn human_in_command_and_transient_phase_gate_motion() {
    let mut p = enforced(PlatformFamily::Drone);
    p.auto_max_step = Step::RequestSafeState;
    let mut c = ctx(PlatformFamily::Drone);
    let free = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::MovingFast, &c);
    assert!(!free.requires_human_approval);
    c.control = ControlMode::Teleop;
    let t = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::MovingFast, &c);
    assert!(t.requires_human_approval);
    assert!(t.rationale.contains(|r| *r == Reason::HumanInCommand));
    c.control = ControlMode::Autonomous;
    c.phase = MissionPhase::Takeoff;
    let t = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::MovingFast, &c);
    assert!(t.requires_human_approval);
    assert!(t.rationale.contains(|r| *r == Reason::TransientPhase));
    c.connectivity = Connectivity::Disconnected;
    let t = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::MovingFast, &c);
    assert!(t
        .rationale
        .contains(|r| *r == Reason::ApprovalChannelUnavailable));
}

#[test]
fn platform_mismatch_records_only() {
    let p = enforced(PlatformFamily::Ugv);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &ctx(PlatformFamily::Drone),
    );
    assert_eq!(plan.actions, vec![ResponseAction::Record]);
    assert!(plan.requires_human_approval);
}

#[test]
fn terminate_only_when_idle_and_allowed() {
    let mut p = enforced(PlatformFamily::Ugv);
    p.default_restrict = vec![RestrictTarget::Process, RestrictTarget::Participant];
    let c = ctx(PlatformFamily::Ugv);
    let plan = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::Idle, &c);
    assert!(!has_terminate(&plan), "policy default forbids termination");
    p.allow_terminate_when_idle = true;
    let plan = plan_stateless(&p, &dev(Severity::High), "s", SafetyState::Idle, &c);
    assert!(plan.actions.contains(&ResponseAction::Restrict {
        target: RestrictTarget::Process,
        terminate_process: true
    }));
    assert!(plan.actions.contains(&ResponseAction::Restrict {
        target: RestrictTarget::Participant,
        terminate_process: false
    }));
    for state in SafetyState::ALL
        .into_iter()
        .filter(|s| *s != SafetyState::Idle)
    {
        let plan = plan_stateless(&p, &dev(Severity::Critical), "s", state, &c);
        assert!(!has_terminate(&plan), "{state:?}");
    }
}

#[test]
fn rule_overrides_clamp_and_choose_targets() {
    let mut p = enforced(PlatformFamily::Ugv);
    p.rule_overrides = vec![RuleOverride {
        rule: RULE_A.into(),
        min_step: Step::Restrict,
        max_step: Step::LimitMotion,
        restrict: Some(vec![RestrictTarget::Network]),
    }];
    let c = ctx(PlatformFamily::Ugv);
    let low = plan_stateless(&p, &dev(Severity::Low), "s", SafetyState::MovingFast, &c);
    assert_eq!(low.max_step, Step::Restrict);
    assert_eq!(
        low.actions[1],
        ResponseAction::Restrict {
            target: RestrictTarget::Network,
            terminate_process: false
        }
    );
    let crit = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    assert_eq!(crit.max_step, Step::LimitMotion);
    // Other rules use the matrix.
    let other = plan_stateless(
        &p,
        &Deviation::new(RULE_B, Severity::Critical, ""),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    assert_eq!(other.max_step, Step::RequestSafeState);
}

// ---------------------------------------------------------- platforms ---

#[test]
fn platform_safe_behaviours_differ() {
    let cases = [
        (PlatformFamily::Ugv, SafeBehaviour::ControlledStop),
        (PlatformFamily::Amr, SafeBehaviour::ControlledStop),
        (PlatformFamily::Drone, SafeBehaviour::Hold),
        (PlatformFamily::Arm, SafeBehaviour::ProtectiveStopCategory2),
        (PlatformFamily::Other, SafeBehaviour::PlatformDefined),
    ];
    for (platform, b) in cases {
        let p = enforced(platform);
        let plan = plan_stateless(
            &p,
            &dev(Severity::Critical),
            "s",
            SafetyState::CollaborativeHumanNearby,
            &ctx(platform),
        );
        assert_eq!(
            &plan.actions[plan.actions.len() - 2..],
            &[
                ResponseAction::SafePause { behaviour: b },
                ResponseAction::RequestSafeState { behaviour: b }
            ],
            "{platform:?}"
        );
    }
}

#[test]
fn allowed_behaviour_table() {
    use PlatformFamily as P;
    use SafeBehaviour as B;
    let allowed = |p| -> Vec<B> { B::ALL.into_iter().filter(|b| b.allowed_for(p)).collect() };
    assert_eq!(allowed(P::Ugv), vec![B::ControlledStop, B::PlatformDefined]);
    assert_eq!(allowed(P::Amr), vec![B::ControlledStop, B::PlatformDefined]);
    assert_eq!(
        allowed(P::Drone),
        vec![B::Hold, B::ReturnToLaunch, B::PlatformDefined]
    );
    assert_eq!(
        allowed(P::Arm),
        vec![B::ProtectiveStopCategory2, B::PlatformDefined]
    );
    assert_eq!(allowed(P::Other), vec![B::PlatformDefined]);
}

#[test]
fn drone_rtl_policy_and_rejections() {
    let mut p = enforced(PlatformFamily::Drone);
    p.safe_state = SafeBehaviour::ReturnToLaunch;
    p.validate().unwrap();
    for bad in [
        SafeBehaviour::ControlledStop,
        SafeBehaviour::ProtectiveStopCategory2,
    ] {
        let mut q = p.clone();
        q.safe_pause = bad;
        assert!(matches!(
            q.validate(),
            Err(PolicyError::InvalidSafeBehaviour {
                field: "safe_pause",
                ..
            })
        ));
    }
    let mut arm = enforced(PlatformFamily::Arm);
    arm.safe_state = SafeBehaviour::Hold;
    assert!(matches!(
        arm.validate(),
        Err(PolicyError::InvalidSafeBehaviour {
            field: "safe_state",
            ..
        })
    ));
}

#[test]
fn drone_unknown_json_behaviour_is_unrepresentable() {
    let mut v: serde_json::Value =
        serde_json::from_str(&enforced(PlatformFamily::Drone).to_json()).unwrap();
    for b in ["cut_motors", "motor_off", "stop_category_0", "kill"] {
        v["safe_pause"] = serde_json::Value::String(b.into());
        assert!(
            matches!(
                ResponsePolicy::from_json(&v.to_string()),
                Err(PolicyError::Json(_))
            ),
            "{b}"
        );
    }
}

// -------------------------------------------------- escalation / timeline ---

fn esc_policy() -> ResponsePolicy {
    let mut p = enforced(PlatformFamily::Ugv);
    p.escalation = EscalationPolicy {
        window_ms: 10_000,
        threshold: 3,
        max_escalation_steps: 2,
        ceiling: Step::LimitMotion,
        quiet_period_ms: 60_000,
        min_reissue_interval_ms: 1_000,
    };
    p
}

#[test]
fn repeated_deviations_escalate_one_step_bounded() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    let mut steps = Vec::new();
    for i in 0..9u64 {
        let plan = r.plan(&dev(Severity::Low), "guid1", s, &c, i * 2_000);
        steps.push((plan.max_step, plan.suppressed));
    }
    use Step::*;
    // Spacing 2 s > re-issue interval 1 s, so held re-issues are not suppressed.
    assert_eq!(
        steps,
        vec![
            (Record, false),
            (Record, false),
            (Restrict, false),
            (Restrict, false),
            (Restrict, false),
            (LimitMotion, false),
            (LimitMotion, false),
            (LimitMotion, false),
            (LimitMotion, false),
        ]
    );
    assert_eq!(r.escalation_level("guid1"), 2);
}

#[test]
fn spaced_deviations_do_not_escalate() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    for i in 0..20u64 {
        let plan = r.plan(
            &dev(Severity::Low),
            "g",
            SafetyState::MovingFast,
            &c,
            i * 6_000,
        );
        assert_eq!(plan.max_step, Step::Record, "i={i}");
    }
    assert_eq!(r.escalation_level("g"), 0);
}

#[test]
fn escalation_respects_rule_cap_and_ceiling() {
    let mut p = esc_policy();
    p.rule_overrides.push(RuleOverride {
        rule: RULE_A.into(),
        min_step: Step::Record,
        max_step: Step::Restrict,
        restrict: None,
    });
    let mut r = Responder::new(p).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let mut max = Step::Record;
    for i in 0..30u64 {
        max = max.max(
            r.plan(
                &dev(Severity::Low),
                "g",
                SafetyState::MovingFast,
                &c,
                i * 100,
            )
            .max_step,
        );
    }
    assert_eq!(max, Step::Restrict);
}

#[test]
fn hold_and_rate_limit_prevent_oscillation() {
    // Changed for review finding 2: this test used to open with a Critical
    // (RequestSafeState, awaiting approval) and expected it to suppress later
    // plans, including another source's. Counting approval-pending plans as
    // "issued" and limiting robot-wide was the bug. Now only auto-executable
    // plans are remembered, per (source, rule); other sources are only subject
    // to the motion guard, which keeps their Record/Restrict actions.
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    let high = r.plan(&dev(Severity::High), "g", s, &c, 0);
    assert_eq!(high.max_step, Step::LimitMotion);
    assert!(!high.requires_human_approval && !high.suppressed);
    // Lower-severity repeat (same source, same rule) within the interval:
    // suppressed to Record.
    let low = r.plan(&dev(Severity::Low), "g", s, &c, 500);
    assert!(low.suppressed);
    assert_eq!(low.actions, vec![ResponseAction::Record]);
    assert!(low
        .rationale
        .contains(|x| matches!(x, Reason::RateLimited { since_ms: 500 })));
    // After the interval: held at LimitMotion, never de-escalated.
    let low = r.plan(&dev(Severity::Low), "g", s, &c, 5_000);
    assert_eq!(low.max_step, Step::LimitMotion);
    assert!(!low.suppressed);
    assert!(low.rationale.contains(|x| matches!(x, Reason::Held { .. })));
    // Another source, higher severity than the in-force motion request (Low,
    // held): passes in full, never downgraded.
    let other = r.plan(&dev(Severity::High), "h", s, &c, 5_100);
    assert!(!other.suppressed);
    assert_eq!(other.max_step, Step::LimitMotion);
    // A third source, same severity and step as the in-force request: its
    // redundant LimitMotion is dropped, its own Restrict is kept, and it is
    // not "suppressed".
    let third = r.plan(&dev(Severity::High), "k", s, &c, 5_200);
    assert!(!third.suppressed);
    assert_eq!(third.max_step, Step::Restrict);
    assert!(third
        .actions
        .iter()
        .any(|a| matches!(a, ResponseAction::Restrict { .. })));
    assert!(third.rationale.contains(|x| matches!(
        x,
        Reason::MotionAlreadyRequested {
            step: Step::LimitMotion,
            since_ms: 100
        }
    )));
    // Same source, different rule: not rate limited by the other rule.
    let rule_b = r.plan(
        &Deviation::new(RULE_B, Severity::High, ""),
        "h",
        s,
        &c,
        5_300,
    );
    assert!(!rule_b.suppressed);
    assert_eq!(rule_b.max_step, Step::Restrict);
    // A plan awaiting approval is never suppressed, and does not count.
    let crit = r.plan(&dev(Severity::Critical), "k", s, &c, 5_400);
    assert!(crit.requires_human_approval && !crit.suppressed);
    assert_eq!(crit.max_step, Step::RequestSafeState);
    let crit2 = r.plan(&dev(Severity::Critical), "k", s, &c, 5_500);
    assert!(!crit2.suppressed);
    assert_eq!(crit2.max_step, Step::RequestSafeState);
}

#[test]
fn approval_pending_plans_do_not_mute_other_sources() {
    // Regression for review finding 2 (see also tests/review_poc.rs).
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    // 30 rounds x 2 fresh sources stays under MAX_SOURCES, so no source
    // shares the overflow bucket's escalation state.
    for k in 0..30u64 {
        let t = k * 200;
        let decoy = r.plan(&dev(Severity::Critical), &format!("decoy-{k}"), s, &c, t);
        assert!(decoy.requires_human_approval);
        // A fresh real source each time: always gets the full auto plan.
        let real = r.plan(
            &Deviation::new(RULE_B, Severity::High, ""),
            &format!("real-{k}"),
            s,
            &c,
            t + 1,
        );
        assert!(!real.suppressed, "k={k}");
        assert!(!real.requires_human_approval);
        if k == 0 {
            assert_eq!(real.max_step, Step::LimitMotion);
        } else {
            // Motion already requested by real-0 within the interval or by a
            // later re-issue; the source-specific Restrict is never dropped.
            assert!(real.max_step >= Step::Restrict, "k={k}");
        }
    }
}

#[test]
fn motion_guard_never_downgrades_higher_severity_or_step() {
    let mut p = esc_policy();
    p.auto_max_step = Step::RequestSafeState;
    let mut r = Responder::new(p).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    // Decoys keep a High LimitMotion request in force.
    let d = r.plan(&dev(Severity::High), "decoy", s, &c, 0);
    assert_eq!(d.max_step, Step::LimitMotion);
    // Higher step and severity from another source: passes untouched.
    let crit = r.plan(&dev(Severity::Critical), "real", s, &c, 10);
    assert_eq!(crit.max_step, Step::RequestSafeState);
    assert!(!crit.suppressed && !crit.requires_human_approval);
    // Now the reference is (RequestSafeState, Critical). A High decoy from a
    // fresh source cannot change it, and the next real Critical from yet
    // another source keeps only its Restrict (all motion already requested).
    r.plan(&dev(Severity::High), "decoy2", s, &c, 20);
    let crit2 = r.plan(&dev(Severity::Critical), "real2", s, &c, 30);
    assert_eq!(crit2.max_step, Step::Restrict);
    assert!(!crit2.suppressed);
    // After the interval the full plan is issued again.
    let crit3 = r.plan(&dev(Severity::Critical), "real3", s, &c, 2_000);
    assert_eq!(crit3.max_step, Step::RequestSafeState);
}

#[test]
fn rate_limit_memory_is_bounded_and_eviction_is_fail_active() {
    let mut p = esc_policy();
    p.escalation.min_reissue_interval_ms = 60_000;
    // No escalation: sources beyond MAX_SOURCES share the overflow bucket,
    // which would otherwise escalate; this test is about the rate limiter.
    p.escalation.max_escalation_steps = 0;
    let mut r = Responder::new(p).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::Idle; // High -> Restrict, auto.
    for i in 0..(MAX_REISSUE_KEYS as u64 * 4) {
        let plan = r.plan(&dev(Severity::High), &format!("s{i}"), s, &c, i);
        assert_eq!(plan.max_step, Step::Restrict);
        assert!(!plan.suppressed);
        assert!(r.rate_limit_entries() <= MAX_REISSUE_KEYS);
    }
    // "s0" was evicted long ago: its repeat is re-issued, not suppressed.
    let again = r.plan(&dev(Severity::High), "s0", s, &c, 5_000);
    assert!(!again.suppressed);
    // A recent key is still remembered.
    let recent = r.plan(
        &dev(Severity::High),
        &format!("s{}", MAX_REISSUE_KEYS as u64 * 4 - 1),
        s,
        &c,
        5_001,
    );
    assert!(recent.suppressed);
    // Acknowledging a source clears its rate-limit memory.
    assert!(r.acknowledge(
        Some(&format!("s{}", MAX_REISSUE_KEYS as u64 * 4 - 1)),
        5_002
    ));
    let after_ack = r.plan(
        &dev(Severity::High),
        &format!("s{}", MAX_REISSUE_KEYS as u64 * 4 - 1),
        s,
        &c,
        5_003,
    );
    assert!(!after_ack.suppressed);
}

#[test]
fn observe_mode_deviation_is_record_only_and_stateless() {
    // Regression for review finding 1 (see also tests/review_poc.rs).
    let p = enforced(PlatformFamily::Ugv);
    let c = ctx(PlatformFamily::Ugv);
    for state in SafetyState::ALL {
        for sev in SEVS {
            let d = dev(sev).with_mode(Mode::Observe);
            let plan = plan_stateless(&p, &d, "s", state, &c);
            assert!(plan.observe_only, "{state:?} {sev:?}");
            assert_eq!(plan.actions, vec![ResponseAction::Record]);
            assert!(!plan.requires_human_approval);
            assert!(plan.would_have.is_some());
            assert!(plan
                .rationale
                .contains(|r| *r == Reason::ObserveModeDeviation));
            assert_eq!(check_invariants_for_deviation(&plan, &d, state, &c), Ok(()));
        }
    }
    // Stateful: observe deviations touch no state, but would_have reflects the
    // source's current hold.
    let mut r = Responder::new(esc_policy()).unwrap();
    let s = SafetyState::MovingFast;
    for i in 0..10 {
        let o = r.plan(
            &dev(Severity::Critical).with_mode(Mode::Observe),
            &format!("o{i}"),
            s,
            &c,
            i,
        );
        assert!(o.observe_only && o.max_step == Step::Record);
    }
    assert_eq!(r.tracked_sources(), 0);
    assert_eq!(r.rate_limit_entries(), 0);
    r.plan(&dev(Severity::High), "g", s, &c, 100);
    for i in 0..10 {
        r.plan(
            &dev(Severity::Low).with_mode(Mode::Observe),
            "g",
            s,
            &c,
            101 + i,
        );
    }
    assert_eq!(r.escalation_level("g"), 0);
    let o = r.plan(
        &dev(Severity::Low).with_mode(Mode::Observe),
        "g",
        s,
        &c,
        200,
    );
    assert_eq!(o.would_have.as_ref().unwrap().max_step, Step::LimitMotion);
}

#[test]
fn check_invariants_for_deviation_rejects_acting_on_observe_deviation() {
    let p = enforced(PlatformFamily::Ugv);
    let c = ctx(PlatformFamily::Ugv);
    let enforce_dev = dev(Severity::High);
    let observe_dev = dev(Severity::High).with_mode(Mode::Observe);
    let acting = plan_stateless(&p, &enforce_dev, "s", SafetyState::MovingFast, &c);
    assert!(acting.max_step > Step::Record);
    assert_eq!(
        check_invariants(&acting, SafetyState::MovingFast, &c),
        Ok(())
    );
    assert_eq!(
        check_invariants_for_deviation(&acting, &observe_dev, SafetyState::MovingFast, &c),
        Err(Violation::ObserveOnlyDeviationActed)
    );
    // Record-only but not flagged observe_only: also rejected.
    let mut rec = acting.clone();
    rec.actions = vec![ResponseAction::Record];
    rec.max_step = Step::Record;
    assert_eq!(
        check_invariants_for_deviation(&rec, &observe_dev, SafetyState::MovingFast, &c),
        Err(Violation::ObserveOnlyDeviationActed)
    );
    rec.observe_only = true;
    assert_eq!(
        check_invariants_for_deviation(&rec, &observe_dev, SafetyState::MovingFast, &c),
        Ok(())
    );
    // The backstop replaces such a plan with Record + approval, observe_only.
    let fixed = crate::planner::enforce(acting, &observe_dev, SafetyState::MovingFast, &c);
    assert_eq!(fixed.actions, vec![ResponseAction::Record]);
    assert!(fixed.observe_only && fixed.requires_human_approval);
}

#[test]
fn escalation_is_never_delayed_by_rate_limit() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    assert_eq!(
        r.plan(&dev(Severity::High), "g", s, &c, 0).max_step,
        Step::LimitMotion
    );
    let crit = r.plan(&dev(Severity::Critical), "h", s, &c, 1);
    assert!(!crit.suppressed);
    assert_eq!(crit.max_step, Step::RequestSafeState);
}

#[test]
fn quiet_period_de_escalates() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    r.plan(&dev(Severity::Critical), "g", s, &c, 0);
    let quiet = r.plan(&dev(Severity::Low), "g", s, &c, 60_000);
    assert_eq!(quiet.max_step, Step::Record);
    assert!(!quiet.suppressed);
    assert_eq!(r.tracked_sources(), 1);
}

#[test]
fn acknowledge_de_escalates() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    for i in 0..6 {
        r.plan(&dev(Severity::Low), "g", s, &c, i * 10);
    }
    assert_eq!(r.escalation_level("g"), 2);
    assert!(r.acknowledge(Some("g"), 100));
    assert_eq!(r.escalation_level("g"), 0);
    assert!(!r.acknowledge(Some("nope"), 100));
    // Rate limiter still remembers the robot-wide issue; full ack clears it.
    r.plan(&dev(Severity::Critical), "g", s, &c, 200);
    assert!(r.acknowledge(None, 300));
    let p = r.plan(&dev(Severity::High), "g", s, &c, 301);
    assert_eq!(p.max_step, Step::LimitMotion);
    assert!(!p.suppressed);
}

#[test]
fn hold_survives_estop_release_until_ack() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    r.plan(
        &dev(Severity::Critical),
        "g",
        SafetyState::MovingFast,
        &c,
        0,
    );
    let e = r.plan(
        &dev(Severity::Low),
        "g",
        SafetyState::EStopActive,
        &c,
        2_000,
    );
    assert_eq!(e.actions, vec![ResponseAction::Record]);
    let after = r.plan(&dev(Severity::Low), "g", SafetyState::MovingSlow, &c, 4_000);
    assert_eq!(after.max_step, Step::RequestSafeState);
}

#[test]
fn deviation_storm_is_bounded_and_monotone() {
    // Changed for review finding 2: this used to assert that at most ~24 plans
    // above Record were issued robot-wide for 20k deviations from 10k
    // sources, i.e. that the robot-wide limiter muted almost every source
    // (the bug). Now every source keeps its own response; what stays bounded
    // is (a) memory, (b) the robot-wide re-issue of motion-affecting AUTO
    // steps, which is monotone in (step, severity) within each interval, and
    // (c) `suppressed` only ever hits a repeat of the same (source, rule).
    let p = esc_policy();
    let interval = p.escalation.min_reissue_interval_ms;
    let mut r = Responder::new(p).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let mut rng = Rng(42);
    let mut last_issued = Step::Record;
    let mut motion_issues = 0;
    let mut window: Option<(u64, Step, Severity)> = None;
    let mut auto_seen: std::collections::HashMap<String, (u64, Step)> = Default::default();
    let n = 20_000u64;
    for i in 0..n {
        let src = format!("guid-{}", rng.below(10_000));
        let sev = rng.pick(&SEVS);
        let plan = r.plan(
            &Deviation::new(RULE_A, sev, ""),
            &src,
            SafetyState::MovingFast,
            &c,
            i,
        );
        assert!(r.tracked_sources() <= MAX_SOURCES);
        assert!(r.rate_limit_entries() <= MAX_REISSUE_KEYS);
        last_issued = last_issued.max(plan.max_step);
        if plan.suppressed {
            let (t, step) = auto_seen
                .get(&src)
                .copied()
                .expect("suppressed without prior issue");
            assert!(i - t < interval, "stale suppression of {src}");
            assert!(step > Step::Record);
        }
        let auto = plan.max_step > Step::Record && !plan.requires_human_approval;
        if auto {
            auto_seen.insert(src.clone(), (i, plan.max_step));
        }
        if auto && plan.max_step.is_motion_affecting() {
            motion_issues += 1;
            if let Some((t, st, sv)) = window {
                if i - t < interval {
                    assert!(
                        plan.max_step > st || plan.severity > sv,
                        "non-monotone at {i}"
                    );
                }
            }
            window = Some((i, plan.max_step, plan.severity));
        }
    }
    // Per interval at most |rungs| + |severities| strictly increasing pairs.
    let intervals = n / interval + 1;
    assert!(
        motion_issues <= 7 * intervals,
        "motion issues {motion_issues}"
    );
    assert_eq!(last_issued, Step::RequestSafeState);
}

#[test]
fn overflow_bucket_shares_escalation() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    for i in 0..MAX_SOURCES {
        r.plan(
            &dev(Severity::Low),
            &format!("s{i}"),
            SafetyState::Idle,
            &c,
            i as u64,
        );
    }
    assert_eq!(r.tracked_sources(), MAX_SOURCES);
    // Three brand-new sources -> all land in overflow -> overflow escalates.
    for i in 0..3 {
        r.plan(
            &dev(Severity::Low),
            &format!("new{i}"),
            SafetyState::Idle,
            &c,
            100 + i,
        );
    }
    assert_eq!(r.tracked_sources(), MAX_SOURCES);
    assert_eq!(r.escalation_level(OVERFLOW_SOURCE), 1);
    // Existing sources keep their own state.
    assert_eq!(r.escalation_level("s0"), 0);
}

#[test]
fn hostile_source_keys_and_clock() {
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let long = "é".repeat(1_000);
    let plan = r.plan(&dev(Severity::Low), &long, SafetyState::Idle, &c, u64::MAX);
    assert!(plan.source.len() <= MAX_SOURCE_KEY_LEN);
    // Clock going backwards: no panic, treated as no time elapsed.
    let p2 = r.plan(&dev(Severity::Low), "", SafetyState::Idle, &c, 0);
    assert_eq!(p2.max_step, Step::Record);
    r.plan(&dev(Severity::Low), &long, SafetyState::Idle, &c, 5);
    // Third hit for the long key at the same (clamped) instant -> escalates.
    r.plan(&dev(Severity::Low), &long, SafetyState::Idle, &c, 5);
    assert_eq!(r.escalation_level(&long), 1);
}

// ------------------------------------------- flood / bounded-state siblings ---

fn has_limit(p: &ResponsePlan) -> bool {
    p.actions
        .iter()
        .any(|a| matches!(a, ResponseAction::LimitMotion { .. }))
}

fn has_restrict(p: &ResponsePlan) -> bool {
    p.actions
        .iter()
        .any(|a| matches!(a, ResponseAction::Restrict { .. }))
}

#[test]
fn overflow_flood_cannot_turn_auto_response_into_approval() {
    // Decoys fill the source table, then one more lands in the shared
    // overflow bucket with a Critical deviation (MovingFast -> safe state,
    // above the auto ceiling: approval). Its desired step is held by the
    // bucket. A real High deviation from a new source would then inherit
    // that hold and only get Record + approval; it must instead get the
    // auto LimitMotion a fresh source gets.
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    let crit = dev(Severity::Critical);
    for i in 0..=MAX_SOURCES {
        let p = r.plan(&crit, &format!("decoy-{i}"), s, &c, i as u64);
        assert!(p.requires_human_approval);
    }
    assert_eq!(r.tracked_sources(), MAX_SOURCES);
    let real = r.plan(&dev(Severity::High), "real", s, &c, 100);
    let alone = plan_stateless(r.policy(), &dev(Severity::High), "real", s, &c);
    assert!(!alone.requires_human_approval && has_limit(&alone));
    assert!(!real.requires_human_approval, "{real:?}");
    assert!(!real.suppressed);
    assert!(has_limit(&real) && has_restrict(&real), "{real:?}");
    assert!(real
        .rationale
        .contains(|x| matches!(x, Reason::OverflowStateNotApplied { .. })));
    assert_eq!(
        check_invariants_for_deviation(&real, &dev(Severity::High), s, &c),
        Ok(())
    );
    // A real Critical in overflow still gets its (approval) plan: shared state
    // is only bypassed when that makes the plan more automatic.
    let real_crit = r.plan(&crit, "real-crit", s, &c, 101);
    assert!(real_crit.requires_human_approval);
    assert_eq!(real_crit.max_step, Step::RequestSafeState);
    // Tracked (non-overflow) sources are unaffected by the fallback.
    let tracked = r.plan(&dev(Severity::High), "decoy-0", s, &c, 102);
    assert!(!tracked
        .rationale
        .contains(|x| matches!(x, Reason::OverflowStateNotApplied { .. })));
}

#[test]
fn long_key_prefix_collision_cannot_suppress_legit_source() {
    let mut p = esc_policy();
    p.escalation.min_reissue_interval_ms = 60_000;
    let mut r = Responder::new(p).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::Idle; // High -> Restrict, auto.
    let prefix = "/opt/vendor/".to_string() + &"x".repeat(200);
    let legit = format!("{prefix}/legit_driver");
    let evil = format!("{prefix}/evil");
    let a = r.plan(&dev(Severity::High), &evil, s, &c, 0);
    assert!(has_restrict(&a) && !a.suppressed);
    // Same first MAX_SOURCE_KEY_LEN bytes: used to share the rate-limit
    // entry, so the legit source's Restrict was suppressed.
    let b = r.plan(&dev(Severity::High), &legit, s, &c, 10);
    assert!(!b.suppressed, "{b:?}");
    assert!(has_restrict(&b));
    // plan.source stays the deterministic plain truncation.
    assert_eq!(b.source.len(), MAX_SOURCE_KEY_LEN);
    assert!(legit.starts_with(&b.source));
    // A genuine repeat of the long key is still rate limited.
    let again = r.plan(&dev(Severity::High), &evil, s, &c, 20);
    assert!(again.suppressed);
    // Escalation state is per full key too.
    r.plan(&dev(Severity::High), &evil, s, &c, 30);
    assert_eq!(r.escalation_level(&evil), 1);
    assert_eq!(r.escalation_level(&legit), 0);
    assert_eq!(r.tracked_sources(), 2);
    // Acknowledge resolves the same identity.
    assert!(r.acknowledge(Some(&evil), 40));
    assert_eq!(r.escalation_level(&evil), 0);
    assert!(!r.plan(&dev(Severity::High), &evil, s, &c, 50).suppressed);
}

#[test]
fn motion_guard_is_short_lived_and_cleared_by_estop_and_ack() {
    let mut p = esc_policy();
    p.escalation.min_reissue_interval_ms = 60_000;
    let c = ctx(PlatformFamily::Ugv);
    let fast = SafetyState::MovingFast;
    let high = dev(Severity::High);

    // Control: within the guard window the redundant motion part is dropped.
    let mut r = Responder::new(p.clone()).unwrap();
    assert!(has_limit(&r.plan(&high, "decoy", fast, &c, 0)));
    let dropped = r.plan(&high, "real", fast, &c, 1_000);
    assert!(!has_limit(&dropped) && has_restrict(&dropped));
    // Capped at MAX_MOTION_GUARD_MS even though the interval is 60 s.
    let later = r.plan(&high, "real2", fast, &c, MAX_MOTION_GUARD_MS);
    assert!(has_limit(&later), "{later:?}");

    // E-stop / safe state observed: earlier motion requests are superseded.
    for engaged in [SafetyState::EStopActive, SafetyState::SafeStateActive] {
        let mut r = Responder::new(p.clone()).unwrap();
        r.plan(&high, "decoy", fast, &c, 0);
        let e = r.plan(&dev(Severity::Low), "other", engaged, &c, 100);
        assert_eq!(e.actions, vec![ResponseAction::Record]);
        let real = r.plan(&high, "real", fast, &c, 200);
        assert!(has_limit(&real), "{engaged:?}: {real:?}");
        // Same (source, rule) repeat after the safe state: its motion part
        // is re-requested, not suppressed (entry lowered to Restrict).
        let mut r = Responder::new(p.clone()).unwrap();
        r.plan(&high, "g", fast, &c, 0);
        r.plan(&dev(Severity::Low), "x", engaged, &c, 100);
        let again = r.plan(&high, "g", fast, &c, 200);
        assert!(!again.suppressed && has_limit(&again), "{again:?}");
        // ...while a Restrict-level repeat is still rate limited.
        let mut r = Responder::new(p.clone()).unwrap();
        r.plan(&high, "g", SafetyState::Idle, &c, 0);
        r.plan(&dev(Severity::Low), "x", engaged, &c, 100);
        assert!(r.plan(&high, "g", SafetyState::Idle, &c, 200).suppressed);
    }

    // Any operator acknowledgement forgets the guard.
    let mut r = Responder::new(p).unwrap();
    r.plan(&high, "decoy", fast, &c, 0);
    assert!(r.acknowledge(Some("decoy"), 100));
    assert!(has_limit(&r.plan(&high, "real", fast, &c, 200)));
}

#[test]
fn flood_never_exceeds_safe_state_request_or_acts_under_estop() {
    // Randomized flood: fresh, repeated, long and overflow source keys, all
    // severities and states. Every stateful plan must satisfy the planner
    // invariants, never contain more than RequestSafeState, be Record-only
    // while the safety system is engaged, and memory stays bounded.
    let mut p = esc_policy();
    p.auto_max_step = Step::RequestSafeState;
    p.escalation.ceiling = Step::RequestSafeState;
    let mut r = Responder::new(p).unwrap();
    let mut rng = Rng(7);
    let long = "L".repeat(300);
    for i in 0..30_000u64 {
        let src = match rng.below(4) {
            0 => format!("fresh-{i}"),
            1 => format!("g{}", rng.below(8)),
            2 => format!("{long}{}", rng.below(4)),
            _ => OVERFLOW_SOURCE.to_string(),
        };
        let state = rng.pick(&SafetyState::ALL);
        let mut c = ctx(PlatformFamily::Ugv);
        c.control = rng.pick(&ControlMode::ALL);
        c.phase = rng.pick(&MissionPhase::ALL);
        let mut d = dev(rng.pick(&SEVS));
        if rng.below(10) == 0 {
            d = d.with_mode(Mode::Observe);
        }
        let plan = r.plan(&d, &src, state, &c, i * 7);
        assert_eq!(
            check_invariants_for_deviation(&plan, &d, state, &c),
            Ok(()),
            "{plan:?}"
        );
        assert!(plan.max_step <= Step::RequestSafeState);
        if state.safety_system_engaged() {
            assert_eq!(plan.actions, vec![ResponseAction::Record]);
        }
        assert!(!has_terminate(&plan));
        assert!(plan.source.len() <= MAX_SOURCE_KEY_LEN);
        assert!(r.tracked_sources() <= MAX_SOURCES);
        assert!(r.rate_limit_entries() <= MAX_REISSUE_KEYS);
    }
}

// ---------------------------------------------------------------- policy ---

#[test]
fn policy_json_round_trip() {
    for platform in PlatformFamily::ALL {
        let p = enforced(platform);
        let back = ResponsePolicy::from_json(&p.to_json()).unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn example_policy_file_is_valid() {
    let p = ResponsePolicy::from_json(include_str!("../../../config/response-policy.example.json"))
        .expect("config/response-policy.example.json must validate");
    assert_eq!(p.schema, SCHEMA);
    assert!(
        !p.oem_validated,
        "the example must not claim OEM validation"
    );
    assert!(!p.rule_overrides.is_empty());
}

fn json_with(edit: impl Fn(&mut serde_json::Value)) -> Result<ResponsePolicy, PolicyError> {
    let mut v: serde_json::Value =
        serde_json::from_str(&enforced(PlatformFamily::Ugv).to_json()).unwrap();
    edit(&mut v);
    ResponsePolicy::from_json(&v.to_string())
}

#[test]
fn policy_rejects_exceeding_invariants() {
    use serde_json::json;
    assert!(matches!(
        json_with(|v| v["matrix"]["estop_active"]["critical"] = json!("request_safe_state")),
        Err(PolicyError::SafetySystemCell {
            state: SafetyState::EStopActive,
            ..
        })
    ));
    assert!(matches!(
        json_with(|v| v["matrix"]["safe_state_active"]["low"] = json!("restrict")),
        Err(PolicyError::SafetySystemCell {
            state: SafetyState::SafeStateActive,
            ..
        })
    ));
    // Steps beyond the ladder don't exist.
    for s in [
        "kill_process",
        "actuate",
        "override_estop",
        "cut_power",
        "6",
    ] {
        assert!(
            matches!(
                json_with(|v| v["matrix"]["idle"]["critical"] = json!(s)),
                Err(PolicyError::Json(_))
            ),
            "{s}"
        );
    }
    assert!(matches!(
        json_with(|v| v["safe_pause"] = json!("hold")),
        Err(PolicyError::InvalidSafeBehaviour { .. })
    ));
    for f in [json!(0.0), json!(-0.5), json!(1.5), json!(f64::MAX)] {
        let r = json_with(|v| v["limit_motion_factor"] = f.clone());
        assert!(r.is_err(), "{f}");
    }
    let text = enforced(PlatformFamily::Ugv).to_json().replace(
        "\"limit_motion_factor\": 0.5",
        "\"limit_motion_factor\": 1e400",
    );
    assert!(text.contains("1e400"));
    assert!(ResponsePolicy::from_json(&text).is_err());
    let mut p = enforced(PlatformFamily::Ugv);
    p.limit_motion_factor = f64::NAN;
    assert!(matches!(
        p.validate(),
        Err(PolicyError::LimitMotionFactor(_))
    ));
    assert!(Responder::new(p).is_err());
}

#[test]
fn policy_rejects_malformed() {
    use serde_json::json;
    for bad in ["", "{", "null", "[]", "{\"schema\":1}", "\u{0}"] {
        assert!(
            matches!(ResponsePolicy::from_json(bad), Err(PolicyError::Json(_))),
            "{bad:?}"
        );
    }
    assert!(matches!(
        json_with(|v| v["schema"] = json!("v0")),
        Err(PolicyError::Schema(_))
    ));
    assert!(matches!(
        json_with(|v| v["model"] = json!("")),
        Err(PolicyError::Model(_))
    ));
    assert!(matches!(
        json_with(|v| v["model"] = json!("a\nb")),
        Err(PolicyError::Model(_))
    ));
    assert!(matches!(
        json_with(|v| v["surprise"] = json!(1)),
        Err(PolicyError::Json(_))
    ));
    assert!(matches!(
        json_with(|v| {
            v["matrix"].as_object_mut().unwrap().remove("unknown");
        }),
        Err(PolicyError::Json(_))
    ));
    assert!(matches!(
        json_with(|v| v["default_restrict"] = json!([])),
        Err(PolicyError::EmptyRestrictTargets)
    ));
    assert!(matches!(
        json_with(|v| v["default_restrict"] = json!(["network", "network"])),
        Err(PolicyError::DuplicateRestrictTarget)
    ));
    let ov = |rule: &str| json!({"rule": rule, "max_step": "restrict"});
    assert!(matches!(
        json_with(|v| v["rule_overrides"] = json!([ov(RULE_A), ov(RULE_A)])),
        Err(PolicyError::DuplicateRule(_))
    ));
    for bad in ["", "has space", "x/../y", &"a".repeat(129)] {
        assert!(
            matches!(
                json_with(|v| v["rule_overrides"] = json!([ov(bad)])),
                Err(PolicyError::BadRuleId(_))
            ),
            "{bad}"
        );
    }
    assert!(matches!(
        json_with(|v| v["rule_overrides"] =
            json!([{"rule": RULE_A, "min_step": "safe_pause", "max_step": "restrict"}])),
        Err(PolicyError::OverrideRange { .. })
    ));
    assert!(matches!(
        json_with(|v| v["rule_overrides"] = json!([{"rule": RULE_A, "restrict": []}])),
        Err(PolicyError::EmptyRestrictTargets)
    ));
    let many: Vec<_> = (0..=MAX_RULE_OVERRIDES)
        .map(|i| ov(&format!("r.{i}")))
        .collect();
    assert!(matches!(
        json_with(|v| v["rule_overrides"] = json!(many)),
        Err(PolicyError::TooManyOverrides(_))
    ));
    for (k, val) in [
        ("threshold", json!(1)),
        ("threshold", json!(65)),
        ("max_escalation_steps", json!(3)),
        ("window_ms", json!(0)),
        ("window_ms", json!(86_400_001u64)),
        ("quiet_period_ms", json!(1)),
        ("min_reissue_interval_ms", json!(10_000_000u64)),
    ] {
        assert!(
            matches!(
                json_with(|v| v["escalation"][k] = val.clone()),
                Err(PolicyError::Escalation(_))
            ),
            "{k}={val}"
        );
    }
    assert!(matches!(
        json_with(|v| v["escalation"]["threshold"] = json!(-1)),
        Err(PolicyError::Json(_))
    ));
    // Errors render.
    assert!(!PolicyError::Escalation("x").to_string().is_empty());
}

#[test]
fn override_defaults_apply() {
    let p = json_with(|v| v["rule_overrides"] = serde_json::json!([{"rule": RULE_A}])).unwrap();
    let o = p.override_for(RULE_A).unwrap();
    assert_eq!(
        (o.min_step, o.max_step, o.restrict.clone()),
        (Step::Record, Step::RequestSafeState, None)
    );
}

// --------------------------------------------------------- action catalog ---

#[test]
fn catalog_is_one_consistent_list() {
    assert_eq!(CATALOG.len(), ActionId::ALL.len());
    for (i, id) in ActionId::ALL.into_iter().enumerate() {
        let c = id.spec();
        assert_eq!(c, CATALOG[i]);
        assert_eq!(c.id, id);
        assert!(!c.autonomous, "{} must never be autonomous", c.name);
        assert_eq!(c.wire_name, format!("robot_{}", c.name));
        assert_eq!(ActionId::parse(c.name), Some(id));
        assert_eq!(ActionId::parse_wire(c.wire_name), Some(id));
        assert_eq!(
            serde_json::to_value(id).unwrap(),
            serde_json::json!(c.name),
            "serde name = catalog name"
        );
        // GA executes only reversible actions, or ones with no effect on
        // the robot (evidence capture).
        assert!(
            !c.executable_in_ga || c.reversible || !c.has_effect,
            "{}",
            c.name
        );
        assert_eq!(c.has_effect, id != ActionId::RecordEvidence, "{}", c.name);
        assert_eq!(
            c.process_target_may_de_energise,
            id == ActionId::QuarantineNode,
            "{}",
            c.name
        );
        assert_eq!(
            c.executable_in_ga,
            c.ga_execution != GaExecution::PlanOnly,
            "{}",
            c.name
        );
        // Irreversible or possibly de-energising actions need two people.
        if (!c.reversible && c.has_effect) || c.may_de_energise {
            assert_eq!(c.approval, Approval::TwoPerson, "{}", c.name);
        }
        assert!(c.step <= Step::RequestSafeState);
    }
    let names: Vec<&str> = ActionId::ALL.iter().map(|a| a.as_str()).collect();
    assert_eq!(
        names,
        [
            "restrict_motion",
            "quarantine_node",
            "isolate_network",
            "record_evidence",
            "safe_pause",
            "request_safe_state",
            "rollback_config"
        ]
    );
    let executed: Vec<&str> = CATALOG
        .iter()
        .filter(|c| c.ga_execution == GaExecution::Executor)
        .map(|c| c.name)
        .collect();
    assert_eq!(
        executed,
        [
            "restrict_motion",
            "quarantine_node",
            "isolate_network",
            "record_evidence"
        ]
    );
    assert_eq!(
        ActionId::SafePause.spec().ga_execution,
        GaExecution::PlatformAdapter
    );
    for a in [ActionId::RequestSafeState, ActionId::RollbackConfig] {
        assert!(!a.executable_in_ga() && !a.reversible());
        assert_eq!(a.approval(), Approval::TwoPerson);
    }
    let de: Vec<ActionId> = ActionId::ALL
        .into_iter()
        .filter(|a| a.may_de_energise())
        .collect();
    assert_eq!(
        de,
        [
            ActionId::SafePause,
            ActionId::RequestSafeState,
            ActionId::RollbackConfig
        ]
    );
    // Evidence is never "reverted" (L3).
    assert!(!ActionId::RecordEvidence.reversible());
    // L4: the new name is written; the old `analyst` is still read.
    assert_eq!(
        serde_json::to_value(Approval::Single).unwrap(),
        serde_json::json!("single")
    );
    for name in ["single", "analyst"] {
        assert_eq!(
            serde_json::from_value::<Approval>(serde_json::json!(name)).unwrap(),
            Approval::Single
        );
    }
    assert_eq!(
        serde_json::from_value::<Approval>(serde_json::json!("two_person")).unwrap(),
        Approval::TwoPerson
    );
    assert_eq!(ActionId::parse("robot_safe_pause"), None);
    assert_eq!(ActionId::parse_wire("safe_pause"), None);
}

#[test]
fn every_ladder_action_maps_into_the_catalog() {
    let id = |a: ResponseAction| for_action(&a);
    assert_eq!(id(ResponseAction::Record), ActionId::RecordEvidence);
    assert_eq!(
        id(ResponseAction::Restrict {
            target: RestrictTarget::Network,
            terminate_process: false
        }),
        ActionId::IsolateNetwork
    );
    for t in [RestrictTarget::Participant, RestrictTarget::Process] {
        assert_eq!(
            id(ResponseAction::Restrict {
                target: t,
                terminate_process: false
            }),
            ActionId::QuarantineNode
        );
    }
    assert_eq!(
        id(ResponseAction::LimitMotion { factor: 0.5 }),
        ActionId::RestrictMotion
    );
    let pause = spec_for(&ResponseAction::SafePause {
        behaviour: SafeBehaviour::Hold,
    });
    assert_eq!(
        (pause.wire_name, pause.approval),
        ("robot_safe_pause", Approval::TwoPerson)
    );
    let safe = spec_for(&ResponseAction::RequestSafeState {
        behaviour: SafeBehaviour::Hold,
    });
    assert_eq!(
        (safe.wire_name, safe.approval),
        ("robot_request_safe_state", Approval::TwoPerson)
    );
    // The catalog step of every planned action is its ladder step.
    let mut all = vec![
        ResponseAction::Record,
        ResponseAction::LimitMotion { factor: 0.5 },
        ResponseAction::SafePause {
            behaviour: SafeBehaviour::Hold,
        },
        ResponseAction::RequestSafeState {
            behaviour: SafeBehaviour::Hold,
        },
    ];
    all.extend(RestrictTarget::ALL.map(|t| ResponseAction::Restrict {
        target: t,
        terminate_process: false,
    }));
    for a in all {
        assert_eq!(spec_for(&a).step, a.step(), "{a:?}");
    }
}

// ------------------------------------------------------------ morphology ---

fn morph(platform: PlatformFamily, m: Morphology) -> ResponsePolicy {
    let mut p = enforced(platform);
    p.morphology = m;
    p
}

fn ctx_m(platform: PlatformFamily, m: Morphology) -> OperationalContext {
    OperationalContext {
        morphology: m,
        ..ctx(platform)
    }
}

fn has_de_energising(actions: &[ResponseAction]) -> bool {
    actions.iter().any(|a| for_action(a).may_de_energise())
}

#[test]
fn morphology_defaults_to_unspecified_and_parses() {
    assert_eq!(Morphology::default(), Morphology::Unspecified);
    let base = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    assert_eq!(base.morphology, Morphology::Unspecified);
    // Unvalidated, non-`other` policy without the field: loads, unspecified.
    let mut v: serde_json::Value = serde_json::from_str(&base.to_json()).unwrap();
    assert!(
        v.get("morphology").is_none(),
        "unspecified is not serialised"
    );
    let p = ResponsePolicy::from_json(&v.to_string()).unwrap();
    assert_eq!(p.morphology, Morphology::Unspecified);
    for m in Morphology::ALL {
        v["morphology"] = serde_json::to_value(m).unwrap();
        assert_eq!(v["morphology"], serde_json::json!(m.as_str()));
        assert_eq!(
            ResponsePolicy::from_json(&v.to_string())
                .unwrap()
                .morphology,
            m
        );
    }
    v["morphology"] = serde_json::json!("biped");
    assert!(matches!(
        ResponsePolicy::from_json(&v.to_string()),
        Err(PolicyError::Json(_))
    ));
    let fall: Vec<Morphology> = Morphology::ALL
        .into_iter()
        .filter(|m| m.falls_when_de_energised())
        .collect();
    assert_eq!(fall, [Morphology::Humanoid, Morphology::Unspecified]);
    let balance: Vec<Morphology> = Morphology::ALL
        .into_iter()
        .filter(|m| m.needs_active_balance())
        .collect();
    assert_eq!(
        balance,
        [
            Morphology::Humanoid,
            Morphology::Quadruped,
            Morphology::Unspecified
        ]
    );
}

#[test]
fn morphology_is_required_when_validated_or_platform_other() {
    // H1: validated without morphology.
    let mut p = enforced(PlatformFamily::Ugv);
    p.morphology = Morphology::Unspecified;
    assert_eq!(
        p.validate(),
        Err(PolicyError::MorphologyRequired {
            platform: PlatformFamily::Ugv,
            oem_validated: true
        })
    );
    // H1: platform `other`, even unvalidated.
    let p = ResponsePolicy::conservative_default(PlatformFamily::Other);
    assert!(matches!(
        p.validate(),
        Err(PolicyError::MorphologyRequired { .. })
    ));
    // Explicit `unspecified` is the same as absent.
    let mut v: serde_json::Value =
        serde_json::from_str(&enforced(PlatformFamily::Arm).to_json()).unwrap();
    v["morphology"] = serde_json::json!("unspecified");
    assert!(matches!(
        ResponsePolicy::from_json(&v.to_string()),
        Err(PolicyError::MorphologyRequired { .. })
    ));
    assert!(PolicyError::MorphologyRequired {
        platform: PlatformFamily::Other,
        oem_validated: false
    }
    .to_string()
    .contains("morphology is required"));
    // Unspecified (unvalidated, non-`other`) plans like a humanoid.
    let mut p = enforced(PlatformFamily::Ugv);
    p.morphology = Morphology::Unspecified;
    let c = ctx_m(PlatformFamily::Ugv, Morphology::Unspecified);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    assert!(!has_de_energising(&plan.actions) && !plan.advisory.is_empty());
    assert!(plan.requires_human_approval);
}

#[test]
fn humanoid_never_gets_executable_safe_pause_or_safe_state() {
    for platform in PlatformFamily::ALL {
        let p = morph(platform, Morphology::Humanoid);
        let c = ctx_m(platform, Morphology::Humanoid);
        for state in SafetyState::ALL {
            for sev in SEVS {
                let plan = plan_stateless(&p, &dev(sev), "s", state, &c);
                assert!(
                    !has_de_energising(&plan.actions),
                    "{platform:?} {state:?} {sev:?}: {:?}",
                    plan.actions
                );
                assert!(plan.max_step <= Step::LimitMotion);
                assert_eq!(check_invariants(&plan, state, &c), Ok(()));
                let wanted = p.matrix.get(sev, state);
                if wanted >= Step::SafePause && !state.safety_system_engaged() {
                    if p.safe_pause.allowed_for(platform) {
                        // Advisory carries what would have been requested.
                        assert!(has_de_energising(&plan.advisory), "{state:?} {sev:?}");
                    }
                    assert!(plan.rationale.contains(|r| matches!(
                        r,
                        Reason::DeEnergisingAdvisoryOnly {
                            morphology: Morphology::Humanoid,
                            ..
                        }
                    )));
                    // M1: the substitute always waits for a human, and with
                    // an empty `fall_safe_restrict` it adds no network or
                    // participant restriction.
                    assert!(plan.requires_human_approval, "{plan:?}");
                    assert!(plan.actions.contains(&ResponseAction::LimitMotion {
                        factor: p.limit_motion_factor,
                    }));
                    assert!(!plan.actions.contains(&ResponseAction::Restrict {
                        target: RestrictTarget::Network,
                        terminate_process: false,
                    }));
                } else {
                    assert!(plan.advisory.is_empty());
                }
            }
        }
    }
}

#[test]
fn humanoid_substitutes_only_the_oem_validated_restrict_targets() {
    let mut p = morph(PlatformFamily::Other, Morphology::Humanoid);
    p.auto_max_step = Step::RequestSafeState;
    p.fall_safe_restrict = vec![RestrictTarget::Network];
    p.validate().unwrap();
    let c = ctx_m(PlatformFamily::Other, Morphology::Humanoid);
    let state = SafetyState::CollaborativeHumanNearby;
    let plan = plan_stateless(&p, &dev(Severity::Critical), "s", state, &c);
    assert_eq!(
        plan.actions,
        vec![
            ResponseAction::Record,
            ResponseAction::Restrict {
                target: RestrictTarget::Network,
                terminate_process: false
            },
            ResponseAction::Restrict {
                target: RestrictTarget::Participant,
                terminate_process: false
            },
            ResponseAction::LimitMotion { factor: 0.5 },
        ],
        "default_restrict participant + listed network"
    );
    assert!(
        plan.requires_human_approval,
        "above auto ceiling is not enough"
    );
    assert_eq!(check_invariants(&plan, state, &c), Ok(()));
    // An auto-executable substitute is an invariant violation.
    let mut bad = plan.clone();
    bad.requires_human_approval = false;
    assert_eq!(
        check_invariants(&bad, state, &c),
        Err(Violation::SubstituteWithoutApproval)
    );
    // fall_safe_restrict validation.
    p.fall_safe_restrict = vec![RestrictTarget::Process];
    assert!(matches!(
        p.validate(),
        Err(PolicyError::FallSafeRestrict(_))
    ));
    p.fall_safe_restrict = vec![RestrictTarget::Network, RestrictTarget::Network];
    assert_eq!(p.validate(), Err(PolicyError::DuplicateRestrictTarget));
    let mut q = morph(PlatformFamily::Other, Morphology::Quadruped);
    q.fall_safe_restrict = vec![RestrictTarget::Network];
    assert!(matches!(
        q.validate(),
        Err(PolicyError::FallSafeRestrict(_))
    ));
}

#[test]
fn balancing_robots_never_terminate_and_quarantine_processes_only_with_approval() {
    for m in [Morphology::Humanoid, Morphology::Quadruped] {
        // H2: validation refuses terminate-when-idle.
        let mut p = morph(PlatformFamily::Other, m);
        p.allow_terminate_when_idle = true;
        assert_eq!(p.validate(), Err(PolicyError::TerminateOnBalancingRobot(m)));
        // A policy that bypassed validation still never terminates, and the
        // process quarantine waits for a human even while idle.
        p.default_restrict = vec![RestrictTarget::Process];
        p.auto_max_step = Step::RequestSafeState;
        let c = ctx_m(PlatformFamily::Other, m);
        let plan = plan_stateless(&p, &dev(Severity::Medium), "s", SafetyState::Idle, &c);
        assert_eq!(
            plan.actions,
            vec![
                ResponseAction::Record,
                ResponseAction::Restrict {
                    target: RestrictTarget::Process,
                    terminate_process: false
                }
            ],
            "{m:?}"
        );
        assert!(plan.requires_human_approval, "{m:?}");
        assert!(plan
            .rationale
            .contains(|r| matches!(r, Reason::ProcessQuarantineNeedsApproval { .. })));
        assert_eq!(check_invariants(&plan, SafetyState::Idle, &c), Ok(()));
        let mut bad = plan.clone();
        bad.requires_human_approval = false;
        assert_eq!(
            check_invariants(&bad, SafetyState::Idle, &c),
            Err(Violation::ProcessQuarantineWithoutApproval)
        );
        bad.requires_human_approval = true;
        bad.actions[1] = ResponseAction::Restrict {
            target: RestrictTarget::Process,
            terminate_process: true,
        };
        assert_eq!(
            check_invariants(&bad, SafetyState::Idle, &c),
            Err(Violation::TerminateOnBalancingRobot)
        );
    }
    // A wheeled robot keeps the idle termination.
    let mut p = morph(PlatformFamily::Ugv, Morphology::WheeledMobile);
    p.allow_terminate_when_idle = true;
    p.default_restrict = vec![RestrictTarget::Process];
    p.validate().unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let plan = plan_stateless(&p, &dev(Severity::Medium), "s", SafetyState::Idle, &c);
    assert!(has_terminate(&plan) && !plan.requires_human_approval);
}

#[test]
fn balancing_robots_have_a_motion_factor_floor() {
    for m in [Morphology::Humanoid, Morphology::Quadruped] {
        let mut p = morph(PlatformFamily::Other, m);
        p.limit_motion_factor = 1e-9;
        assert!(matches!(
            p.validate(),
            Err(PolicyError::MotionFactorBelowFloor { .. })
        ));
        p.limit_motion_factor = 0.19;
        assert!(p.validate().is_err(), "default floor 0.2");
        p.min_motion_factor = 0.1;
        p.validate().unwrap();
        for bad in [0.0, 0.049, 1.01, f64::NAN, f64::INFINITY] {
            p.min_motion_factor = bad;
            assert!(
                matches!(p.validate(), Err(PolicyError::MinMotionFactor(_))),
                "{bad}"
            );
        }
        // Bypassing validation: the factor is dropped and approval needed.
        p.min_motion_factor = 0.2;
        p.limit_motion_factor = 1e-9;
        let c = ctx_m(PlatformFamily::Other, m);
        let state = SafetyState::MovingSlow;
        let plan = plan_stateless(&p, &dev(Severity::High), "s", state, &c);
        assert!(!plan
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::LimitMotion { .. })));
        assert!(plan.requires_human_approval);
        // The invariant has a hard floor.
        let mut bad = plan.clone();
        bad.actions
            .push(ResponseAction::LimitMotion { factor: 0.01 });
        bad.max_step = Step::LimitMotion;
        assert_eq!(
            check_invariants(&bad, state, &c),
            Err(Violation::MotionBelowFloor)
        );
    }
    // Wheeled: no floor beyond (0, 1].
    let mut p = enforced(PlatformFamily::Ugv);
    p.limit_motion_factor = 0.01;
    p.validate().unwrap();
}

#[test]
fn morphology_mismatch_records_only_and_plans_for_another_body_are_refused() {
    // The policy says wheeled, the context (the robot's own config) says
    // humanoid: the planner only records.
    let p = enforced(PlatformFamily::Other);
    let c = ctx_m(PlatformFamily::Other, Morphology::Humanoid);
    let state = SafetyState::MovingFast;
    let plan = plan_stateless(&p, &dev(Severity::Critical), "s", state, &c);
    assert_eq!(plan.actions, vec![ResponseAction::Record]);
    assert!(plan.requires_human_approval);
    assert!(plan
        .rationale
        .contains(|r| matches!(r, Reason::MorphologyMismatch { .. })));
    assert_eq!(check_invariants(&plan, state, &c), Ok(()));
    // M4: a plan that claims `other` but acts is refused by a humanoid
    // executor, whatever the plan says about itself.
    let lying = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        state,
        &ctx(PlatformFamily::Other),
    );
    assert!(has_de_energising(&lying.actions));
    assert_eq!(
        check_invariants(&lying, state, &c),
        Err(Violation::MorphologyMismatch)
    );
}

#[test]
fn other_morphologies_keep_the_full_ladder() {
    let state = SafetyState::CollaborativeHumanNearby;
    for m in Morphology::ALL {
        for platform in PlatformFamily::ALL {
            let p = morph(platform, m);
            let c = ctx_m(platform, m);
            let plan = plan_stateless(&p, &dev(Severity::Critical), "s", state, &c);
            assert_eq!(check_invariants(&plan, state, &c), Ok(()));
            assert_eq!(plan.morphology, m);
            if m.falls_when_de_energised() {
                assert_eq!(plan.max_step, Step::LimitMotion, "{platform:?}");
                assert_eq!(plan.advisory.len(), 2, "{platform:?}");
            } else {
                assert_eq!(plan.max_step, Step::RequestSafeState, "{m:?} {platform:?}");
                assert!(plan.advisory.is_empty());
                assert!(has_de_energising(&plan.actions));
                // Same actions as the family's statically stable body.
                let base = plan_stateless(
                    &enforced(platform),
                    &dev(Severity::Critical),
                    "s",
                    state,
                    &ctx(platform),
                );
                assert_eq!(plan.actions, base.actions, "{m:?} {platform:?}");
            }
        }
    }
}

#[test]
fn humanoid_observe_mode_keeps_advisory_in_would_have_only() {
    let mut p = morph(PlatformFamily::Other, Morphology::Humanoid);
    p.oem_validated = false;
    let c = ctx_m(PlatformFamily::Other, Morphology::Humanoid);
    let state = SafetyState::MovingFast;
    let plan = plan_stateless(&p, &dev(Severity::Critical), "s", state, &c);
    assert!(plan.observe_only);
    assert!(plan.advisory.is_empty());
    let w = plan.would_have.as_ref().unwrap();
    assert!(!w.advisory.is_empty() && !has_de_energising(&w.actions));
    assert!(w.requires_human_approval);
    assert_eq!(check_invariants(&plan, state, &c), Ok(()));
}

#[test]
fn humanoid_escalation_never_reaches_de_energising() {
    let mut p = morph(PlatformFamily::Other, Morphology::Humanoid);
    p.escalation.ceiling = Step::RequestSafeState;
    p.escalation.max_escalation_steps = 2;
    let c = ctx_m(PlatformFamily::Other, Morphology::Humanoid);
    let mut r = Responder::new(p).unwrap();
    for i in 0..20u64 {
        let plan = r.plan(
            &dev(Severity::High),
            "guid-1",
            SafetyState::MovingSlow,
            &c,
            i * 1000,
        );
        assert!(!has_de_energising(&plan.actions), "{i}: {plan:?}");
    }
}

#[test]
fn invariant_rejects_de_energising_on_humanoid_plans() {
    let p = enforced(PlatformFamily::Other);
    let c = ctx(PlatformFamily::Other);
    let hc = ctx_m(PlatformFamily::Other, Morphology::Humanoid);
    let state = SafetyState::MovingFast;
    let mut plan = plan_stateless(&p, &dev(Severity::Critical), "s", state, &c);
    assert!(has_de_energising(&plan.actions));
    assert_eq!(check_invariants(&plan, state, &c), Ok(()));
    // The plan relabelled as humanoid: refused by a checker that knows the
    // robot as `other` (mismatch) and by one that knows it as humanoid.
    plan.morphology = Morphology::Humanoid;
    assert_eq!(
        check_invariants(&plan, state, &c),
        Err(Violation::MorphologyMismatch)
    );
    assert_eq!(
        check_invariants(&plan, state, &hc),
        Err(Violation::DeEnergisingOnFallProneMorphology)
    );
    // Advisory may only hold safe pause / safe state valid for the platform.
    let mut plan = plan_stateless(&p, &dev(Severity::Low), "s", state, &c);
    plan.advisory = vec![ResponseAction::Record];
    assert_eq!(
        check_invariants(&plan, state, &c),
        Err(Violation::BadAdvisory)
    );
    plan.advisory = vec![ResponseAction::SafePause {
        behaviour: SafeBehaviour::Hold,
    }];
    assert_eq!(
        check_invariants(&plan, state, &c),
        Err(Violation::BadAdvisory),
        "hold is not valid for `other`"
    );
    plan.advisory = vec![ResponseAction::SafePause {
        behaviour: SafeBehaviour::PlatformDefined,
    }];
    assert_eq!(check_invariants(&plan, state, &c), Ok(()));
}

#[test]
fn humanoid_plan_json_round_trips_and_default_omits_new_fields() {
    let p = morph(PlatformFamily::Other, Morphology::Humanoid);
    let c = ctx_m(PlatformFamily::Other, Morphology::Humanoid);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::MovingFast,
        &c,
    );
    let j = serde_json::to_string(&plan).unwrap();
    assert!(j.contains("\"morphology\":\"humanoid\""));
    assert!(j.contains("\"advisory\":["));
    let back: ResponsePlan = serde_json::from_str(&j).unwrap();
    assert_eq!(back, plan);
    // A plan without the field (older records) reads as unspecified: the
    // conservative reading.
    let mut v: serde_json::Value = serde_json::from_str(&j).unwrap();
    v.as_object_mut().unwrap().remove("morphology");
    let old: ResponsePlan = serde_json::from_value(v).unwrap();
    assert_eq!(old.morphology, Morphology::Unspecified);
    let plain = plan_stateless(
        &enforced(PlatformFamily::Ugv),
        &dev(Severity::Low),
        "s",
        SafetyState::MovingFast,
        &ctx(PlatformFamily::Ugv),
    );
    let j = serde_json::to_string(&plain).unwrap();
    assert!(j.contains("\"morphology\":\"wheeled_mobile\"") && !j.contains("advisory"));
    // OperationalContext without `morphology` reads as unspecified.
    let mut v = serde_json::to_value(ctx(PlatformFamily::Ugv)).unwrap();
    v.as_object_mut().unwrap().remove("morphology");
    let c: OperationalContext = serde_json::from_value(v).unwrap();
    assert_eq!(c.morphology, Morphology::Unspecified);
}

#[test]
fn plan_serializes_to_json() {
    let p = enforced(PlatformFamily::Arm);
    let plan = plan_stateless(
        &p,
        &dev(Severity::Critical),
        "s",
        SafetyState::Unknown,
        &ctx(PlatformFamily::Arm),
    );
    let j = serde_json::to_string(&plan).unwrap();
    assert!(j.contains("\"step\":\"request_safe_state\""));
    assert!(j.contains("protective_stop_category2"));
    let back: ResponsePlan = serde_json::from_str(&j).unwrap();
    assert_eq!(back, plan);
}

/// Findings contract 2.5 (sales-readiness T45): a host finding's own id
/// `robot.host.<rule>` takes its own override, else the one a policy wrote
/// for the pre-2.5 single id `robot.host.pulsar_threat`; nothing else does.
#[test]
fn host_rule_overrides_fall_back_to_the_pulsar_threat_override() {
    let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    let ov = |rule: &str, max: Step| RuleOverride {
        rule: rule.into(),
        min_step: Step::Record,
        max_step: max,
        restrict: None,
    };
    assert!(p.override_for("robot.host.interactive_shell").is_none());
    p.rule_overrides
        .push(ov(policy::HOST_THREAT_FALLBACK_RULE, Step::Record));
    p.validate().unwrap();
    for id in [
        "robot.host.interactive_shell",
        "robot.host.pulsar_threat",
        "robot.host.anything_new",
    ] {
        assert_eq!(
            p.override_for(id).map(|o| o.rule.as_str()),
            Some("robot.host.pulsar_threat"),
            "{id}"
        );
    }
    assert!(p.override_for(RULE_A).is_none());
    assert!(p.override_for("robot.hostile.x").is_none());
    // An override of the rule's own id wins.
    p.rule_overrides
        .push(ov("robot.host.interactive_shell", Step::Restrict));
    assert_eq!(
        p.override_for("robot.host.interactive_shell")
            .map(|o| o.max_step),
        Some(Step::Restrict)
    );
}
