//! Shared helpers for the responder integration tests: contexts, policies,
//! an independent oracle for the conservative default matrix, plan
//! predicates and a std-only xorshift PRNG.

#![allow(dead_code)]

use robodr_events::{Deviation, Mode, Severity};
use robodr_responder::*;

pub const SEVERITIES: [Severity; 4] = [
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];
pub const MODES: [Mode; 2] = [Mode::Observe, Mode::Enforce];

/// xorshift64* — deterministic, std-only.
#[derive(Debug, Clone)]
pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        // Zero is a fixed point of xorshift; avoid it.
        XorShift((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }

    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

/// A nominal, autonomous, connected, profile-locked context.
pub fn ctx(platform: PlatformFamily) -> OperationalContext {
    OperationalContext {
        platform,
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: true,
    }
}

/// Every context combination for one platform.
pub fn all_contexts(platform: PlatformFamily) -> Vec<OperationalContext> {
    let mut v = Vec::new();
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
    v
}

/// Conservative default, OEM-validated (enforce mode possible).
pub fn validated(platform: PlatformFamily) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(platform);
    p.oem_validated = true;
    p
}

/// The most aggressive policy `validate` accepts: every cell outside the
/// safety-system states asks for the safe state, nothing needs approval by
/// policy, termination allowed when idle, all restrict targets, two
/// escalation rungs up to the top.
pub fn aggressive(platform: PlatformFamily) -> ResponsePolicy {
    let mut p = validated(platform);
    let top = SeverityRow::uniform(Step::RequestSafeState);
    p.matrix.idle = top;
    p.matrix.moving_slow = top;
    p.matrix.moving_fast = top;
    p.matrix.collaborative_human_nearby = top;
    p.matrix.unknown = top;
    p.auto_max_step = Step::RequestSafeState;
    p.allow_terminate_when_idle = true;
    p.default_restrict = RestrictTarget::ALL.to_vec();
    p.escalation.max_escalation_steps = 2;
    p.escalation.ceiling = Step::RequestSafeState;
    p.validate().expect("aggressive policy must still be valid");
    p
}

pub fn dev(rule: &str, sev: Severity, mode: Mode) -> Deviation {
    Deviation::new(rule.to_string(), sev, "test").with_mode(mode)
}

/// Independent oracle: the conservative default matrix as documented in the
/// crate README (not read back from the code under test).
pub fn default_cell(state: SafetyState, sev: Severity) -> Step {
    use Severity::*;
    use Step::*;
    let row: [Step; 4] = match state {
        SafetyState::Idle => [Record, Restrict, Restrict, SafePause],
        SafetyState::MovingSlow | SafetyState::MovingFast => {
            [Record, Record, LimitMotion, RequestSafeState]
        }
        SafetyState::CollaborativeHumanNearby => [Record, LimitMotion, SafePause, RequestSafeState],
        SafetyState::EStopActive | SafetyState::SafeStateActive => [Record; 4],
        SafetyState::Unknown => [Record, Record, Restrict, RequestSafeState],
    };
    row[match sev {
        Low => 0,
        Medium => 1,
        High => 2,
        Critical => 3,
    }]
}

/// The safe behaviour the conservative default requests per platform.
pub fn default_behaviour(platform: PlatformFamily) -> SafeBehaviour {
    match platform {
        PlatformFamily::Ugv | PlatformFamily::Amr => SafeBehaviour::ControlledStop,
        PlatformFamily::Drone => SafeBehaviour::Hold,
        PlatformFamily::Arm => SafeBehaviour::ProtectiveStopCategory2,
        PlatformFamily::Other => SafeBehaviour::PlatformDefined,
    }
}

pub fn is_record_only(p: &ResponsePlan) -> bool {
    p.actions == vec![ResponseAction::Record] && p.max_step == Step::Record
}

pub fn has_motion(p: &ResponsePlan) -> bool {
    p.actions.iter().any(|a| a.step().is_motion_affecting())
}

pub fn has_terminate(p: &ResponsePlan) -> bool {
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

pub fn has_restrict(p: &ResponsePlan) -> bool {
    p.actions
        .iter()
        .any(|a| matches!(a, ResponseAction::Restrict { .. }))
}

pub fn has_limit(p: &ResponsePlan) -> bool {
    p.actions
        .iter()
        .any(|a| matches!(a, ResponseAction::LimitMotion { .. }))
}

/// Auto-executable: something above Record may run without a human.
pub fn is_eligible(p: &ResponsePlan) -> bool {
    p.max_step > Step::Record && !p.requires_human_approval && !p.observe_only && !p.suppressed
}

/// Invariants every plan must satisfy, whatever produced it. Returns a
/// description of the first violation.
pub fn universal_invariants(
    p: &ResponsePlan,
    d: &Deviation,
    state: SafetyState,
    c: &OperationalContext,
    policy: &ResponsePolicy,
) -> Result<(), String> {
    check_invariants_for_deviation(p, d, state, c).map_err(|v| format!("invariant {v}"))?;
    // Never past the top rung, never anything while the safety system has
    // authority, observe => record only.
    if state.safety_system_engaged() && !is_record_only(p) {
        return Err("acted while the safety system is engaged".into());
    }
    if (d.is_observe_only() || !c.profile_locked || !policy.oem_validated) && !p.observe_only {
        return Err("observe-mode input produced a non-observe plan".into());
    }
    if p.observe_only {
        if !is_record_only(p) || p.requires_human_approval || p.suppressed {
            return Err("observe plan is not plain Record".into());
        }
        if p.would_have.is_none() {
            return Err("observe plan without would_have".into());
        }
    } else if p.would_have.is_some() {
        return Err("enforce plan carries would_have".into());
    }
    if p.suppressed && !is_record_only(p) {
        return Err("suppressed plan is not Record only".into());
    }
    // No process kill while in motion (or ever, unless idle + allowed);
    // also checked on the would-have plan.
    for q in std::iter::once(p).chain(p.would_have.as_deref()) {
        if has_terminate(q) && !(state == SafetyState::Idle && policy.allow_terminate_when_idle) {
            return Err("terminate outside idle/allowed".into());
        }
        if has_motion(q)
            && !q.requires_human_approval
            && (state == SafetyState::Unknown
                || c.control.human_in_command()
                || c.phase.is_transient())
        {
            return Err("motion without approval under a gate".into());
        }
        if q.max_step > policy.auto_max_step && !q.requires_human_approval {
            return Err("above auto ceiling without approval".into());
        }
        if c.platform != policy.platform && !is_record_only(q) {
            return Err("acted on a platform mismatch".into());
        }
        for a in &q.actions {
            match a {
                ResponseAction::SafePause { behaviour }
                | ResponseAction::RequestSafeState { behaviour }
                    if !behaviour.allowed_for(c.platform) =>
                {
                    return Err(format!("{behaviour:?} invalid for {:?}", c.platform));
                }
                ResponseAction::LimitMotion { factor }
                    if !(factor.is_finite() && *factor > 0.0 && *factor <= 1.0) =>
                {
                    return Err("bad limit factor".into());
                }
                _ => {}
            }
        }
    }
    Ok(())
}
