//! Regression tests for the independent review of the vendor-neutral action
//! catalog and the humanoid rule (findings H1, H2, M1, M2).

use robodr_events::{Deviation, Severity};
use robodr_responder::*;
use serde_json::{json, Value};

fn base_json() -> Value {
    serde_json::from_str(include_str!("../../../config/response-policy.example.json")).unwrap()
}

fn humanoid_json() -> Value {
    let mut v = base_json();
    v["platform"] = json!("other");
    v["morphology"] = json!("humanoid");
    v["safe_pause"] = json!("platform_defined");
    v["safe_state"] = json!("platform_defined");
    v["oem_validated"] = json!(true);
    v
}

fn ctx_json(platform: &str) -> OperationalContext {
    serde_json::from_value(json!({
        "platform": platform, "phase": "transit", "connectivity": "connected",
        "control": "autonomous", "operator_present": true, "profile_locked": true,
        "morphology": "humanoid"
    }))
    .unwrap()
}

/// H1: a humanoid policy that forgets `morphology` used to load as `other`
/// and get executable safe pause / safe state.
#[test]
fn h1_validated_or_other_policy_without_morphology_is_rejected() {
    let mut v = humanoid_json();
    v.as_object_mut().unwrap().remove("morphology");
    assert!(ResponsePolicy::from_json(&v.to_string()).is_err());
    let mut v = base_json();
    v.as_object_mut().unwrap().remove("morphology");
    v["oem_validated"] = json!(true);
    assert!(ResponsePolicy::from_json(&v.to_string()).is_err());
}

/// H2: terminate-when-idle is meaningless for a robot that balances while
/// "idle".
#[test]
fn h2_humanoid_policy_refuses_terminate_when_idle() {
    let mut v = humanoid_json();
    v["allow_terminate_when_idle"] = json!(true);
    assert!(ResponsePolicy::from_json(&v.to_string()).is_err());
}

/// H2: process quarantine on an idle humanoid may stop its balance
/// controller; it must wait for a human.
#[test]
fn h2_idle_humanoid_process_quarantine_needs_approval() {
    let mut v = humanoid_json();
    v["default_restrict"] = json!(["process"]);
    let p = ResponsePolicy::from_json(&v.to_string()).unwrap();
    let c = ctx_json("other");
    let d = Deviation::new("robot.x", Severity::Medium, "x");
    let plan = plan_stateless(&p, &d, "s", SafetyState::Idle, &c);
    assert!(plan.actions.iter().any(|a| matches!(
        a,
        ResponseAction::Restrict {
            target: RestrictTarget::Process,
            ..
        }
    )));
    assert!(plan.requires_human_approval, "{plan:?}");
}

/// M1: the humanoid substitutes for safe pause must not be auto-executed.
#[test]
fn m1_humanoid_substitutes_need_approval() {
    let mut v = humanoid_json();
    v["auto_max_step"] = json!("request_safe_state");
    let p = ResponsePolicy::from_json(&v.to_string()).unwrap();
    let c = ctx_json("other");
    let d = Deviation::new("robot.x", Severity::Critical, "x");
    let plan = plan_stateless(&p, &d, "s", SafetyState::CollaborativeHumanNearby, &c);
    assert!(!plan.advisory.is_empty());
    assert!(plan.requires_human_approval, "{plan:?}");
    assert!(!plan.actions.contains(&ResponseAction::Restrict {
        target: RestrictTarget::Network,
        terminate_process: false
    }));
}

/// M2: a near-stop envelope is a fall hazard on a balancing robot.
#[test]
fn m2_humanoid_near_zero_motion_factor_is_rejected() {
    let mut v = humanoid_json();
    v["limit_motion_factor"] = json!(1e-9);
    assert!(ResponsePolicy::from_json(&v.to_string()).is_err());
}

fn ctx_for(p: &ResponsePolicy) -> OperationalContext {
    OperationalContext {
        platform: p.platform,
        morphology: p.morphology,
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: true,
    }
}

/// H1: every in-repo example policy declares its morphology and validates,
/// also once OEM-validated; the Unitree examples are humanoid / quadruped.
#[test]
fn h1_example_policies_declare_morphology_and_validate() {
    let examples = [
        (
            include_str!("../../../config/response-policy.example.json"),
            Morphology::WheeledMobile,
        ),
        (
            include_str!("../../../config/response-policy.unitree-g1.example.json"),
            Morphology::Humanoid,
        ),
        (
            include_str!("../../../config/response-policy.unitree-go2.example.json"),
            Morphology::Quadruped,
        ),
        (
            include_str!("../../robodr-agent/examples/policy-oem-validated.json"),
            Morphology::WheeledMobile,
        ),
    ];
    for (text, want) in examples {
        let p = ResponsePolicy::from_json(text).expect("example policy validates");
        assert_eq!(p.morphology, want);
        let v: Value = serde_json::from_str(text).unwrap();
        assert!(v.get("morphology").is_some(), "declared explicitly");
        // Still valid once the OEM signs it off.
        let mut signed = p.clone();
        signed.oem_validated = true;
        signed.validate().unwrap();
    }
}

/// The Unitree G1 example: no executable safe pause / safe state, every
/// substitute awaits a human, no network cut (fall_safe_restrict empty).
#[test]
fn unitree_g1_example_plans_balance_safe() {
    let mut p = ResponsePolicy::from_json(include_str!(
        "../../../config/response-policy.unitree-g1.example.json"
    ))
    .unwrap();
    p.oem_validated = true;
    assert!(p.fall_safe_restrict.is_empty());
    assert!(!p.allow_terminate_when_idle);
    assert!(p.limit_motion_factor >= p.min_motion_factor);
    let c = ctx_for(&p);
    for state in SafetyState::ALL {
        for sev in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let d = Deviation::new("robot.ros2.unknown_participant", sev, "x");
            let plan = plan_stateless(&p, &d, "s", state, &c);
            assert_eq!(check_invariants(&plan, state, &c), Ok(()));
            assert!(plan.max_step <= Step::LimitMotion, "{plan:?}");
            assert!(!plan.actions.iter().any(|a| matches!(
                a,
                ResponseAction::SafePause { .. } | ResponseAction::RequestSafeState { .. }
            )));
            if !plan.advisory.is_empty() {
                assert!(plan.requires_human_approval);
                assert!(!plan.actions.contains(&ResponseAction::Restrict {
                    target: RestrictTarget::Network,
                    terminate_process: false
                }));
            }
        }
    }
}

/// The Unitree Go2 example keeps an OEM-validated platform-defined safe
/// pause, but never terminates a process.
#[test]
fn unitree_go2_example_keeps_safe_pause_but_never_terminates() {
    let mut p = ResponsePolicy::from_json(include_str!(
        "../../../config/response-policy.unitree-go2.example.json"
    ))
    .unwrap();
    p.oem_validated = true;
    let c = ctx_for(&p);
    let d = Deviation::new("robot.x", Severity::High, "x");
    let plan = plan_stateless(&p, &d, "s", SafetyState::CollaborativeHumanNearby, &c);
    assert!(plan.actions.contains(&ResponseAction::SafePause {
        behaviour: SafeBehaviour::PlatformDefined
    }));
    let mut t = p.clone();
    t.allow_terminate_when_idle = true;
    assert!(matches!(
        t.validate(),
        Err(PolicyError::TerminateOnBalancingRobot(
            Morphology::Quadruped
        ))
    ));
}
