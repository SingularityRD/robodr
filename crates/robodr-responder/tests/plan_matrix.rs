//! Table-driven planner tests: every PlatformFamily x SafetyState x
//! Severity x deviation Mode (observe/enforce), across every operational
//! context, checked against an independent oracle and against "never more
//! aggressive than allowed" bounds.

mod common;

use common::*;
use robodr_events::{Deviation, Mode, Severity};
use robodr_responder::*;

/// The exact plan the conservative default (OEM-validated) must give in a
/// given context, built from the oracle table, not from the code.
fn expected_actions(platform: PlatformFamily, step: Step) -> Vec<ResponseAction> {
    let b = default_behaviour(platform);
    let mut v = vec![ResponseAction::Record];
    if step >= Step::Restrict {
        v.push(ResponseAction::Restrict {
            target: RestrictTarget::Participant,
            terminate_process: false,
        });
    }
    if step >= Step::LimitMotion {
        v.push(ResponseAction::LimitMotion { factor: 0.5 });
    }
    if step >= Step::SafePause {
        v.push(ResponseAction::SafePause { behaviour: b });
    }
    if step >= Step::RequestSafeState {
        v.push(ResponseAction::RequestSafeState { behaviour: b });
    }
    v
}

fn expected_approval(step: Step, state: SafetyState, c: &OperationalContext) -> bool {
    let gated = step.is_motion_affecting()
        && (state == SafetyState::Unknown
            || c.control.human_in_command()
            || c.phase.is_transient());
    gated || step > Step::LimitMotion
}

#[test]
fn every_platform_state_severity_mode_and_context_matches_the_oracle() {
    let mut checked = 0usize;
    for platform in PlatformFamily::ALL {
        for oem_validated in [false, true] {
            let mut policy = ResponsePolicy::conservative_default(platform);
            policy.oem_validated = oem_validated;
            for c in all_contexts(platform) {
                for state in SafetyState::ALL {
                    for sev in SEVERITIES {
                        for mode in MODES {
                            let d = dev("robot.test.rule", sev, mode);
                            let p = plan_stateless(&policy, &d, "src", state, &c);
                            let tag = format!(
                                "{platform:?} oem={oem_validated} {state:?} {sev:?} {mode:?} {c:?}"
                            );
                            universal_invariants(&p, &d, state, &c, &policy)
                                .unwrap_or_else(|e| panic!("{tag}: {e}\n{p:#?}"));

                            let step = default_cell(state, sev);
                            let enforce_actions = expected_actions(platform, step);
                            let approval = expected_approval(step, state, &c);
                            let observe =
                                mode == Mode::Observe || !c.profile_locked || !oem_validated;

                            assert_eq!(p.rule, "robot.test.rule", "{tag}");
                            assert_eq!(p.severity, sev, "{tag}");
                            assert_eq!(p.source, "src", "{tag}");
                            assert_eq!(p.safety_state, state, "{tag}");
                            assert!(!p.suppressed, "{tag}");
                            let enforce_plan = if observe {
                                assert!(p.observe_only, "{tag}");
                                assert!(is_record_only(&p), "{tag}");
                                assert!(!p.requires_human_approval, "{tag}");
                                let w = p.would_have.as_deref().expect("would_have");
                                assert!(w.would_have.is_none(), "{tag}");
                                assert!(!w.observe_only, "{tag}");
                                // Exactly one observe reason, the most specific first.
                                let want = if mode == Mode::Observe {
                                    Reason::ObserveModeDeviation
                                } else if !c.profile_locked {
                                    Reason::ObserveModeProfileUnlocked
                                } else {
                                    Reason::ObserveModePolicyNotValidated
                                };
                                assert_eq!(p.rationale.reasons.last(), Some(&want), "{tag}");
                                w
                            } else {
                                assert!(!p.observe_only, "{tag}");
                                assert!(p.would_have.is_none(), "{tag}");
                                &p
                            };
                            assert_eq!(enforce_plan.actions, enforce_actions, "{tag}");
                            assert_eq!(enforce_plan.max_step, step, "{tag}");
                            assert_eq!(enforce_plan.requires_human_approval, approval, "{tag}");
                            assert_eq!(
                                enforce_plan.rationale.reasons.first(),
                                Some(&Reason::Matrix {
                                    severity: sev,
                                    state,
                                    step
                                }),
                                "{tag}"
                            );
                            if state.safety_system_engaged() {
                                assert!(
                                    enforce_plan
                                        .rationale
                                        .contains(|r| *r == Reason::SafetySystemHasAuthority),
                                    "{tag}"
                                );
                            }
                            let channel_down = approval
                                && c.connectivity == Connectivity::Disconnected
                                && enforce_actions.len() > 1;
                            assert_eq!(
                                enforce_plan
                                    .rationale
                                    .contains(|r| *r == Reason::ApprovalChannelUnavailable),
                                channel_down,
                                "{tag}"
                            );
                            // Pure function: same input, same output.
                            assert_eq!(p, plan_stateless(&policy, &d, "src", state, &c), "{tag}");
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    // 5 platforms x 2 validation x 216 contexts x 7 states x 4 sev x 2 modes.
    assert_eq!(checked, 5 * 2 * 216 * 7 * 4 * 2);
}

#[test]
fn aggressive_policy_is_still_bounded_by_the_code_invariants() {
    for platform in PlatformFamily::ALL {
        let policy = aggressive(platform);
        for c in all_contexts(platform) {
            for state in SafetyState::ALL {
                for sev in SEVERITIES {
                    for mode in MODES {
                        let d = dev("robot.test.rule", sev, mode);
                        let p = plan_stateless(&policy, &d, "src", state, &c);
                        let tag = format!("{platform:?} {state:?} {sev:?} {mode:?} {c:?}");
                        universal_invariants(&p, &d, state, &c, &policy)
                            .unwrap_or_else(|e| panic!("{tag}: {e}\n{p:#?}"));
                        let enforce = p.would_have.as_deref().unwrap_or(&p);
                        if state.safety_system_engaged() {
                            // E-stop / safe state: never override, never compete.
                            assert!(is_record_only(enforce), "{tag}");
                            continue;
                        }
                        assert_eq!(enforce.max_step, Step::RequestSafeState, "{tag}");
                        // Process kill only while idle; quarantine otherwise.
                        let kill = enforce.actions.iter().any(|a| {
                            *a == ResponseAction::Restrict {
                                target: RestrictTarget::Process,
                                terminate_process: true,
                            }
                        });
                        assert_eq!(kill, state == SafetyState::Idle, "{tag}");
                        let quarantine = enforce.actions.iter().any(|a| {
                            *a == ResponseAction::Restrict {
                                target: RestrictTarget::Process,
                                terminate_process: false,
                            }
                        });
                        assert_eq!(quarantine, state != SafetyState::Idle, "{tag}");
                        // Network / participant restrictions never "terminate".
                        for a in &enforce.actions {
                            if let ResponseAction::Restrict {
                                target,
                                terminate_process: true,
                            } = a
                            {
                                assert_eq!(*target, RestrictTarget::Process, "{tag}");
                            }
                        }
                        let gated = state == SafetyState::Unknown
                            || c.control.human_in_command()
                            || c.phase.is_transient();
                        assert_eq!(enforce.requires_human_approval, gated, "{tag}");
                        // Observe mode never executes even with this policy.
                        if mode == Mode::Observe || !c.profile_locked {
                            assert!(p.observe_only && is_record_only(&p), "{tag}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn platform_mismatch_is_record_only_with_approval_for_every_pair() {
    for policy_platform in PlatformFamily::ALL {
        let policy = aggressive(policy_platform);
        for robot in PlatformFamily::ALL {
            if robot == policy_platform {
                continue;
            }
            for state in SafetyState::ALL {
                for sev in SEVERITIES {
                    let d = dev("r", sev, Mode::Enforce);
                    let c = ctx(robot);
                    let p = plan_stateless(&policy, &d, "src", state, &c);
                    let tag = format!("{policy_platform:?} on {robot:?} {state:?} {sev:?}");
                    universal_invariants(&p, &d, state, &c, &policy)
                        .unwrap_or_else(|e| panic!("{tag}: {e}"));
                    assert!(is_record_only(&p), "{tag}");
                    assert!(p.requires_human_approval, "{tag}");
                    assert!(
                        p.rationale.contains(|r| matches!(
                            r,
                            Reason::PlatformMismatch { policy, context }
                                if *policy == policy_platform && *context == robot
                        )),
                        "{tag}"
                    );
                }
            }
        }
    }
}

#[test]
fn safe_behaviours_are_platform_specific_and_never_cut_power() {
    for platform in PlatformFamily::ALL {
        let p = plan_stateless(
            &aggressive(platform),
            &dev("r", Severity::Critical, Mode::Enforce),
            "s",
            SafetyState::MovingFast,
            &ctx(platform),
        );
        let b = default_behaviour(platform);
        assert_eq!(
            &p.actions[p.actions.len() - 2..],
            &[
                ResponseAction::SafePause { behaviour: b },
                ResponseAction::RequestSafeState { behaviour: b },
            ],
            "{platform:?}"
        );
        // Nothing past RequestSafeState exists in the serialized vocabulary.
        let json = serde_json::to_string(&p).unwrap();
        for forbidden in ["kill", "power", "motor", "estop_override", "category_0"] {
            assert!(
                !json.contains(forbidden),
                "{platform:?}: {forbidden} in {json}"
            );
        }
    }
    // A drone asks for RTL only if its policy says so, and is never asked to
    // "stop" (controlled stop is not valid for a drone).
    let mut drone = validated(PlatformFamily::Drone);
    drone.safe_state = SafeBehaviour::ReturnToLaunch;
    drone.validate().unwrap();
    drone.safe_state = SafeBehaviour::ControlledStop;
    assert!(matches!(
        drone.validate(),
        Err(PolicyError::InvalidSafeBehaviour { .. })
    ));
}

#[test]
fn observe_mode_never_acts_even_on_the_worst_case() {
    // Critical, human nearby, aggressive policy: observe still only records,
    // and the would-have plan shows what enforcement would have requested.
    for platform in PlatformFamily::ALL {
        let policy = aggressive(platform);
        let c = ctx(platform);
        let d = dev("r", Severity::Critical, Mode::Observe);
        let p = plan_stateless(&policy, &d, "s", SafetyState::CollaborativeHumanNearby, &c);
        assert!(p.observe_only && is_record_only(&p));
        let w = p.would_have.as_deref().unwrap();
        assert_eq!(w.max_step, Step::RequestSafeState);
        // Feeding the observe deviation's would-have plan back as if it were
        // the plan is caught by the deviation-aware check.
        assert_eq!(
            check_invariants_for_deviation(w, &d, SafetyState::CollaborativeHumanNearby, &c),
            Err(Violation::ObserveOnlyDeviationActed)
        );
    }
}

#[test]
fn rule_override_bounds_are_respected_for_every_cell() {
    let mut policy = validated(PlatformFamily::Ugv);
    policy.rule_overrides = vec![
        RuleOverride {
            rule: "capped".into(),
            min_step: Step::Record,
            max_step: Step::Restrict,
            restrict: Some(vec![RestrictTarget::Network]),
        },
        RuleOverride {
            rule: "floored".into(),
            min_step: Step::LimitMotion,
            max_step: Step::RequestSafeState,
            restrict: None,
        },
    ];
    policy.validate().unwrap();
    for state in SafetyState::ALL {
        for sev in SEVERITIES {
            let cell = default_cell(state, sev);
            let c = ctx(PlatformFamily::Ugv);
            let capped =
                plan_stateless(&policy, &Deviation::new("capped", sev, "x"), "s", state, &c);
            assert!(capped.max_step <= Step::Restrict, "{state:?} {sev:?}");
            if capped.max_step == Step::Restrict {
                assert_eq!(
                    capped.actions[1],
                    ResponseAction::Restrict {
                        target: RestrictTarget::Network,
                        terminate_process: false
                    }
                );
            }
            let floored = plan_stateless(
                &policy,
                &Deviation::new("floored", sev, "x"),
                "s",
                state,
                &c,
            );
            if state.safety_system_engaged() {
                // The floor never beats the safety system's authority.
                assert!(is_record_only(&floored), "{state:?} {sev:?}");
            } else {
                assert_eq!(
                    floored.max_step,
                    cell.max(Step::LimitMotion),
                    "{state:?} {sev:?}"
                );
            }
        }
    }
}

#[test]
fn hostile_rule_and_source_strings_do_not_panic_or_leak_into_actions() {
    let policy = aggressive(PlatformFamily::Ugv);
    let long = "x".repeat(100_000);
    let weird = [
        "",
        "\0",
        "\u{202e}rtl",
        "💥💥💥",
        "../../etc/passwd",
        "{\"step\":\"kill\"}",
        long.as_str(),
    ];
    for rule in weird {
        for source in weird {
            for state in SafetyState::ALL {
                let d = Deviation::new(rule.to_string(), Severity::Critical, rule);
                let c = ctx(PlatformFamily::Ugv);
                let p = plan_stateless(&policy, &d, source, state, &c);
                universal_invariants(&p, &d, state, &c, &policy).unwrap();
            }
        }
    }
}
