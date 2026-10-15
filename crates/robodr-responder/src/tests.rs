//! Crate tests: matrix, invariants (exhaustive + randomized), escalation and
//! hysteresis timelines, policy validation, platform differences.

use robodr_events::{Deviation, Severity};

use crate::autosecops::{action_class, Approval, ALL_CLASSES, ROBOTICS_CATEGORY};
use crate::escalation::{MAX_SOURCES, MAX_SOURCE_KEY_LEN, OVERFLOW_SOURCE};
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

fn enforced(platform: PlatformFamily) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(platform);
    p.oem_validated = true;
    p.model = "test-model".into();
    p
}

fn ctx(platform: PlatformFamily) -> OperationalContext {
    OperationalContext {
        platform,
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
    p.allow_terminate_when_idle = r.bool();
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
            let rule = if r.bool() { RULE_A } else { RULE_B };
            let d = Deviation::new(rule, r.pick(&SEVS), "x");
            let src = ["a", "b", "c"][r.below(3)];
            let plan = resp.plan(&d, src, state, &c, now);
            assert_invariants(&plan, &policy, state, &c);
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
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let s = SafetyState::MovingFast;
    let crit = r.plan(&dev(Severity::Critical), "g", s, &c, 0);
    assert_eq!(crit.max_step, Step::RequestSafeState);
    // Lower-severity repeat within the interval: suppressed to Record.
    let low = r.plan(&dev(Severity::Low), "g", s, &c, 500);
    assert!(low.suppressed);
    assert_eq!(low.actions, vec![ResponseAction::Record]);
    assert!(low
        .rationale
        .contains(|x| matches!(x, Reason::RateLimited { since_ms: 500 })));
    // After the interval: held at RequestSafeState, never de-escalated.
    let low = r.plan(&dev(Severity::Low), "g", s, &c, 5_000);
    assert_eq!(low.max_step, Step::RequestSafeState);
    assert!(low.rationale.contains(|x| matches!(x, Reason::Held { .. })));
    // Another source's lower plan right after is suppressed robot-wide.
    let other = r.plan(&dev(Severity::High), "h", s, &c, 5_100);
    assert!(other.suppressed);
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
    let mut r = Responder::new(esc_policy()).unwrap();
    let c = ctx(PlatformFamily::Ugv);
    let mut rng = Rng(42);
    let mut last_issued = Step::Record;
    let mut issued = 0;
    for i in 0..20_000u64 {
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
        if plan.max_step > Step::Record {
            issued += 1;
            last_issued = last_issued.max(plan.max_step);
        }
    }
    // 20k deviations over 20 s with a 1 s re-issue interval: escalations
    // (<= 4 distinct rungs) plus at most one re-issue per second.
    assert!(issued <= 4 + 20, "issued {issued}");
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

// ------------------------------------------------------------- autosecops ---

#[test]
fn autosecops_classes_never_autonomous() {
    for c in ALL_CLASSES {
        assert!(!c.autonomous_eligible, "{}", c.name);
        assert_eq!(c.category, ROBOTICS_CATEGORY);
        assert!(c.name.starts_with("robot_"));
    }
    let name = |a: ResponseAction| action_class(&a).name;
    assert_eq!(name(ResponseAction::Record), "robot_record_evidence");
    assert!(!action_class(&ResponseAction::Record).in_design_doc);
    assert_eq!(
        name(ResponseAction::Restrict {
            target: RestrictTarget::Network,
            terminate_process: false
        }),
        "robot_isolate_network"
    );
    for t in [RestrictTarget::Participant, RestrictTarget::Process] {
        assert_eq!(
            name(ResponseAction::Restrict {
                target: t,
                terminate_process: false
            }),
            "robot_quarantine_node"
        );
    }
    assert_eq!(
        name(ResponseAction::LimitMotion { factor: 0.5 }),
        "robot_restrict_motion"
    );
    let pause = action_class(&ResponseAction::SafePause {
        behaviour: SafeBehaviour::Hold,
    });
    assert_eq!(
        (pause.name, pause.approval),
        ("robot_safe_pause", Approval::TwoPerson)
    );
    let safe = action_class(&ResponseAction::RequestSafeState {
        behaviour: SafeBehaviour::Hold,
    });
    assert_eq!(
        (safe.name, safe.approval),
        ("robot_request_safe_state", Approval::TwoPerson)
    );
    assert!(ALL_CLASSES.iter().filter(|c| c.in_design_doc).count() == 5);
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
