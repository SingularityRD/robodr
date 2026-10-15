//! The pure, stateless decision: deviation x safety state x context x policy
//! → [`ResponsePlan`]. Escalation state is passed in by the caller
//! ([`crate::Responder`]); this module has no memory.
//!
//! Order of evaluation (each stage is recorded in the plan's rationale):
//!
//! 1. matrix cell `policy.matrix[state][severity]`;
//! 2. per-rule override clamps it into `[min_step, max_step]`;
//! 3. escalation adds rungs (bounded by `escalation.ceiling` and the override);
//! 4. hold: never below what this source already earned (no auto de-escalation);
//! 5. context caps: platform mismatch or engaged safety system → Record only;
//! 6. approval gates: unknown state, human in command, take-off/landing,
//!    above `auto_max_step`;
//! 7. build the cumulative action list (Record .. max step);
//! 8. observe mode (profile unlocked or policy not OEM-validated) → Record
//!    only, with the would-have plan attached;
//! 9. invariant backstop: [`check_invariants`]; on violation the plan is
//!    replaced by Record + approval (never reached with a validated policy).

use std::fmt;

use robodr_events::Deviation;

use crate::action::{Rationale, Reason, ResponseAction, ResponsePlan, Step};
use crate::policy::ResponsePolicy;
use crate::state::{Connectivity, OperationalContext, SafetyState};

/// Plan once, with no escalation memory. Equivalent to the first deviation a
/// fresh [`crate::Responder`] sees from a source (minus rate limiting).
pub fn plan_stateless(
    policy: &ResponsePolicy,
    deviation: &Deviation,
    source: &str,
    state: SafetyState,
    ctx: &OperationalContext,
) -> ResponsePlan {
    plan_with(policy, deviation, source, state, ctx, 0, Step::Record).0
}

/// Core planner. Returns the plan and the *desired* step for this source
/// before context caps (what the hold should remember).
pub(crate) fn plan_with(
    policy: &ResponsePolicy,
    deviation: &Deviation,
    source: &str,
    state: SafetyState,
    ctx: &OperationalContext,
    escalation_level: u8,
    held: Step,
) -> (ResponsePlan, Step) {
    let mut why = Rationale::default();
    let sev = deviation.severity;

    // 1. Matrix.
    let mut step = policy.matrix.get(sev, state);
    why.push(Reason::Matrix {
        severity: sev,
        state,
        step,
    });

    // 2. Rule override.
    let mut cap = Step::RequestSafeState;
    let mut targets = policy.default_restrict.as_slice();
    if let Some(o) = policy.override_for(deviation.rule) {
        // validate() guarantees min <= max; guard anyway so clamp can't panic.
        let (lo, hi) = (o.min_step.min(o.max_step), o.max_step);
        let result = step.clamp(lo, hi);
        why.push(Reason::RuleOverride {
            rule: o.rule.clone(),
            min: lo,
            max: hi,
            result,
        });
        step = result;
        cap = hi;
        if let Some(t) = &o.restrict {
            targets = t.as_slice();
        }
    }

    // 3. Escalation (never lowers; bounded by the escalation ceiling and the
    //    rule's own cap).
    if escalation_level > 0 {
        let esc_cap = policy.escalation.ceiling.min(cap);
        let raised = step.raised(escalation_level).min(esc_cap);
        if raised > step {
            step = raised;
            why.push(Reason::Escalated {
                level: escalation_level,
                result: step,
            });
        }
    }

    // 4. Hold.
    if held > step {
        step = held;
        why.push(Reason::Held { step });
    }
    let desired = step;

    // 5. Context caps.
    let mut approval = false;
    if ctx.platform != policy.platform {
        why.push(Reason::PlatformMismatch {
            policy: policy.platform,
            context: ctx.platform,
        });
        step = Step::Record;
        approval = true;
    }
    if state.safety_system_engaged() {
        why.push(Reason::SafetySystemHasAuthority);
        step = Step::Record;
    }

    // 6. Approval gates.
    if step.is_motion_affecting() {
        if state == SafetyState::Unknown {
            why.push(Reason::UnknownSafetyState);
            approval = true;
        }
        if ctx.control.human_in_command() {
            why.push(Reason::HumanInCommand);
            approval = true;
        }
        if ctx.phase.is_transient() {
            why.push(Reason::TransientPhase);
            approval = true;
        }
    }
    if step > policy.auto_max_step {
        why.push(Reason::AboveAutoCeiling {
            auto_max_step: policy.auto_max_step,
        });
        approval = true;
    }

    // 7. Build the cumulative action list.
    let mut actions = vec![ResponseAction::Record];
    if step >= Step::Restrict {
        let terminate_ok = state.is_idle() && policy.allow_terminate_when_idle;
        let mut ts = targets.to_vec();
        ts.sort();
        ts.dedup();
        for t in ts {
            actions.push(ResponseAction::Restrict {
                target: t,
                terminate_process: terminate_ok && t == crate::action::RestrictTarget::Process,
            });
        }
    }
    if step >= Step::LimitMotion {
        let f = policy.limit_motion_factor;
        if f.is_finite() && f > 0.0 && f <= 1.0 {
            actions.push(ResponseAction::LimitMotion { factor: f });
        } else {
            why.push(Reason::InvalidLimitFactor);
            approval = true;
        }
    }
    for (s, b) in [
        (Step::SafePause, policy.safe_pause),
        (Step::RequestSafeState, policy.safe_state),
    ] {
        if step < s {
            break;
        }
        if b.allowed_for(ctx.platform) {
            actions.push(match s {
                Step::SafePause => ResponseAction::SafePause { behaviour: b },
                _ => ResponseAction::RequestSafeState { behaviour: b },
            });
        } else {
            why.push(Reason::InvalidSafeBehaviour { behaviour: b });
            approval = true;
        }
    }
    if approval && ctx.connectivity == Connectivity::Disconnected && actions.len() > 1 {
        why.push(Reason::ApprovalChannelUnavailable);
    }

    let max_step = actions
        .iter()
        .map(|a| a.step())
        .max()
        .unwrap_or(Step::Record);
    let mut plan = ResponsePlan {
        rule: deviation.rule.to_string(),
        severity: sev,
        source: source.to_string(),
        safety_state: state,
        max_step,
        actions,
        requires_human_approval: approval,
        observe_only: false,
        suppressed: false,
        would_have: None,
        rationale: why,
    };

    // 8. Observe mode.
    let observe_reason = if !ctx.profile_locked {
        Some(Reason::ObserveModeProfileUnlocked)
    } else if !policy.oem_validated {
        Some(Reason::ObserveModePolicyNotValidated)
    } else {
        None
    };
    if let Some(r) = observe_reason {
        let mut rationale = plan.rationale.clone();
        rationale.push(r);
        plan = ResponsePlan {
            max_step: Step::Record,
            actions: vec![ResponseAction::Record],
            requires_human_approval: false,
            observe_only: true,
            would_have: Some(Box::new(plan.clone())),
            rationale,
            ..plan
        };
    }

    // 9. Backstop.
    (enforce(plan, state, ctx), desired)
}

/// Replace a plan that violates an invariant with Record + approval. With a
/// validated policy this never triggers; it exists so that a planner bug can
/// only ever make the response *less* active.
pub(crate) fn enforce(
    plan: ResponsePlan,
    state: SafetyState,
    ctx: &OperationalContext,
) -> ResponsePlan {
    match check_invariants(&plan, state, ctx) {
        Ok(()) => plan,
        Err(_) => ResponsePlan {
            max_step: Step::Record,
            actions: vec![ResponseAction::Record],
            requires_human_approval: true,
            would_have: None,
            ..plan
        },
    }
}

/// An invariant a plan broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    NotStartingWithRecord,
    OutOfOrder,
    MaxStepMismatch,
    ActionWhileSafetySystemEngaged,
    ObserveModeNotRecordOnly,
    MotionWithoutApproval,
    TerminateWhileNotIdle,
    TerminateNonProcess,
    BadLimitFactor,
    SafeBehaviourInvalidForPlatform,
    NestedWouldHave,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Check every code-level invariant of a plan against the state and context
/// it was made for. Public so an executor can re-check a plan it received
/// (e.g. from the fleet) before acting on it.
pub fn check_invariants(
    plan: &ResponsePlan,
    state: SafetyState,
    ctx: &OperationalContext,
) -> Result<(), Violation> {
    let a = &plan.actions;
    if a.first() != Some(&ResponseAction::Record) {
        return Err(Violation::NotStartingWithRecord);
    }
    if a.windows(2).any(|w| w[0].step() > w[1].step()) {
        return Err(Violation::OutOfOrder);
    }
    if a.iter().map(|x| x.step()).max() != Some(plan.max_step) {
        return Err(Violation::MaxStepMismatch);
    }
    let only_record = a.iter().all(|x| x.step() == Step::Record);
    if state.safety_system_engaged() && !only_record {
        return Err(Violation::ActionWhileSafetySystemEngaged);
    }
    if plan.observe_only && !only_record {
        return Err(Violation::ObserveModeNotRecordOnly);
    }
    let motion = a.iter().any(|x| x.step().is_motion_affecting());
    if motion
        && !plan.requires_human_approval
        && (state == SafetyState::Unknown
            || ctx.control.human_in_command()
            || ctx.phase.is_transient())
    {
        return Err(Violation::MotionWithoutApproval);
    }
    for x in a {
        match *x {
            ResponseAction::Restrict {
                target,
                terminate_process: true,
            } => {
                if target != crate::action::RestrictTarget::Process {
                    return Err(Violation::TerminateNonProcess);
                }
                if !state.is_idle() {
                    return Err(Violation::TerminateWhileNotIdle);
                }
            }
            ResponseAction::LimitMotion { factor }
                if !(factor.is_finite() && factor > 0.0 && factor <= 1.0) =>
            {
                return Err(Violation::BadLimitFactor);
            }
            ResponseAction::SafePause { behaviour }
            | ResponseAction::RequestSafeState { behaviour }
                if !behaviour.allowed_for(ctx.platform) =>
            {
                return Err(Violation::SafeBehaviourInvalidForPlatform);
            }
            _ => {}
        }
    }
    if let Some(w) = &plan.would_have {
        if w.would_have.is_some() {
            return Err(Violation::NestedWouldHave);
        }
        check_invariants(w, state, ctx)?;
    }
    Ok(())
}
