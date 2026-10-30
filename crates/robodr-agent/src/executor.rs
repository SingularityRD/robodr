//! The seam where plans would leave the agent. **The agent executes
//! nothing.** It hands every plan to an [`Executor`]; the implementations in
//! this crate only discard or log.
//!
//! # Contract for a real executor (not built yet)
//!
//! A real executor (DDS/host enforcement, Motion Firewall envelope change,
//! mission-executive pause, safety-controller request) MUST:
//!
//! 1. re-run [`robodr_responder::check_invariants`] on the plan with the
//!    safety state and context it was made for ([`ExecutionRequest::recheck`])
//!    and act on nothing if it fails;
//! 2. treat [`Disposition::ObserveOnly`], [`Disposition::Suppressed`] and
//!    [`Disposition::RecordOnly`] as "nothing to do" (the agent already
//!    recorded the evidence);
//! 3. for [`Disposition::AwaitingHumanApproval`], do nothing beyond `Record`
//!    until a human approves, and re-check the *current* safety state at
//!    approval time;
//! 4. never send anything to the platform while its safety system is engaged,
//!    and never reset an e-stop or cut power: the plan vocabulary ends at
//!    `request_safe_state`, and the platform's safety controller decides;
//! 5. act on nothing when [`ExecutionRequest::replay`] is set (a replay of
//!    recorded or synthetic input must never reach a robot);
//! 6. only *request*: every step is a request to another component
//!    (DDS/host enforcement, the Motion Firewall gateway, the mission
//!    executive, the safety controller) through an abstract interface. An
//!    executor never writes actuator commands, never commands motion, and
//!    never overrides the e-stop or the platform's command authority;
//! 7. compare the robot's morphology **from its own response policy** with
//!    the plan's and the request context's, and act on nothing if they
//!    differ ([`ExecutionRequest::recheck_for`],
//!    [`ExecutionRequest::steps_without_approval_for`]). A plan's own
//!    `morphology` field is never trusted alone: a plan made (or relabelled)
//!    for a wheeled robot must not reach a humanoid. On a robot that falls
//!    when de-energised (humanoid) an executor never executes `advisory`
//!    actions, and never executes a substitute containment without a
//!    human's approval; on one that needs active balance (humanoid,
//!    quadruped) it never terminates a process and never quarantines one
//!    without approval (see `robodr_responder::Morphology`).
//!
//! **Crypto-erase** (`docs/SECURE-DELIVERY.md` §7.6, Sprint 14b) is the
//! first response that is executed. It is outside the ladder (it destroys
//! the unit's own sealing keys and touches no actuator) and is planned by
//! `robodr_responder::erase::plan_erase`, graded by the safety state like
//! every action (never mid-motion). The unit delivery agent
//! (`robodr-deliverd`) executes it under rules 1-5 above: it re-derives
//! the plan from the trigger, acts on nothing for an unauthenticated or
//! replayed trigger, re-reads the live safety state immediately before
//! acting, journals the intent before the erase and reads the TPM's erase
//! epoch back afterwards. Rule 4's "never cut power" is unaffected.
//!
//! [`ExecutionRequest::steps_without_approval_for`] encodes rules 1-5 and 7
//! for the steps a real executor may request without a human: it re-derives
//! the disposition from the plan (a mislabelled request offers nothing),
//! re-runs the invariants against the executor's own morphology, refuses
//! replays, and refuses when the *current* safety state differs from the one
//! the plan was made for or the safety system is engaged (the plan must then
//! be re-made, not reused). [`ExecutionRequest::steps_without_approval_at`]
//! is the same without the executor's own morphology (it checks the plan
//! against the request context only); a real executor must use the `_for`
//! form.
//!
//! Executors run synchronously inside [`crate::Agent::handle`]: a slow
//! executor slows detection (natural backpressure, nothing queues without
//! bound). A real executor must therefore hand requests to its own bounded
//! queue and never block.

use std::io::Write;

use robodr_ocsf::BlackBoxRef;
use robodr_responder::{
    check_invariants, Morphology, OperationalContext, ResponsePlan, SafetyState, Step, Violation,
};

use crate::outcome::Disposition;

/// One plan offered to an executor.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionRequest<'a> {
    pub plan: &'a ResponsePlan,
    pub disposition: Disposition,
    /// Safety state the plan was made for.
    pub safety_state: SafetyState,
    /// Context the plan was made for (with `profile_locked` as the agent
    /// passed it to the responder).
    pub context: &'a OperationalContext,
    /// Black-box records backing the plan.
    pub evidence: &'a [BlackBoxRef],
    pub finding_id: Option<&'a str>,
    /// The plan comes from a replay (`robodr-replay` or any agent built by
    /// [`crate::replay`]): act on nothing.
    pub replay: bool,
}

impl ExecutionRequest<'_> {
    /// The re-check against the request context only (see module docs; a
    /// real executor uses [`recheck_for`](Self::recheck_for)).
    pub fn recheck(&self) -> Result<(), Violation> {
        check_invariants(self.plan, self.safety_state, self.context)
    }

    /// The mandatory re-check (rules 1 and 7): the invariants hold for the
    /// request context **and** for the same context with the robot's
    /// morphology as the executor's own policy declares it (`own`), and the
    /// request context's morphology is `own`. Any mismatch is
    /// [`Violation::MorphologyMismatch`].
    pub fn recheck_for(&self, own: Morphology) -> Result<(), Violation> {
        if self.context.morphology != own || self.plan.morphology != own {
            return Err(Violation::MorphologyMismatch);
        }
        self.recheck()?;
        let mine = OperationalContext {
            morphology: own,
            ..*self.context
        };
        check_invariants(self.plan, self.safety_state, &mine)
    }

    /// Steps an executor could request without a human, if the safety
    /// state is still the one the plan was made for. See
    /// [`steps_without_approval_at`](Self::steps_without_approval_at), which
    /// a real executor must use with the platform's *current* state.
    pub fn steps_without_approval(&self) -> Vec<Step> {
        self.steps_without_approval_at(self.safety_state)
    }

    /// Steps an executor may request right now without a human, given the
    /// platform's `current` safety state. Empty unless all hold: not a
    /// replay; the disposition given *and* the one re-derived from the plan
    /// are [`Disposition::Eligible`]; the invariants hold; `current` equals
    /// the state the plan was made for; the safety system is not engaged.
    /// `Record` is excluded (already done).
    pub fn steps_without_approval_at(&self, current: SafetyState) -> Vec<Step> {
        self.offer(current, None)
    }

    /// What a real executor may request right now without a human: as
    /// [`steps_without_approval_at`](Self::steps_without_approval_at), and
    /// empty unless [`recheck_for`](Self::recheck_for) passes with the
    /// robot's morphology from the executor's **own** policy (`own`).
    pub fn steps_without_approval_for(&self, current: SafetyState, own: Morphology) -> Vec<Step> {
        self.offer(current, Some(own))
    }

    fn offer(&self, current: SafetyState, own: Option<Morphology>) -> Vec<Step> {
        if own.is_some_and(|m| self.recheck_for(m).is_err()) {
            return Vec::new();
        }
        if self.replay
            || self.disposition != Disposition::Eligible
            || Disposition::of(self.plan) != Disposition::Eligible
            || current != self.safety_state
            || current.safety_system_engaged()
            || self.recheck().is_err()
        {
            return Vec::new();
        }
        self.plan
            .steps()
            .into_iter()
            .filter(|s| *s != Step::Record)
            .collect()
    }
}

/// Receives plans. Implementations must follow the module-level contract.
pub trait Executor {
    fn submit(&mut self, request: &ExecutionRequest<'_>);
}

/// Discards every plan.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    fn submit(&mut self, _request: &ExecutionRequest<'_>) {}
}

/// Writes one line per plan describing what a real executor *would* request
/// (or why it would not), and the result of the invariant re-check. Acts on
/// nothing. Write errors are ignored (logging must not stop detection).
#[derive(Debug)]
pub struct LoggingExecutor<W: Write> {
    out: W,
}

impl<W: Write> LoggingExecutor<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

/// The line [`LoggingExecutor`] writes for a request (without newline).
pub fn describe(request: &ExecutionRequest<'_>) -> String {
    let p = request.plan;
    let check = match request.recheck() {
        Ok(()) => "invariants ok".to_string(),
        Err(v) => format!("INVARIANT VIOLATION {v}: nothing would be requested"),
    };
    let what = match request.disposition {
        Disposition::ObserveOnly => {
            let wh = p
                .would_have
                .as_ref()
                .map(|w| format!(" (enforcement would have planned up to {:?})", w.max_step))
                .unwrap_or_default();
            format!("observe only: record{wh}")
        }
        Disposition::Suppressed => "rate-limited: record only".to_string(),
        Disposition::RecordOnly => "record only".to_string(),
        Disposition::AwaitingHumanApproval => {
            format!("awaiting human approval for steps {:?}", p.steps())
        }
        // Show what a live executor would be offered; a replay itself is
        // offered nothing (see `steps_without_approval_at`).
        Disposition::Eligible => format!(
            "would request {:?} (no approval needed)",
            ExecutionRequest {
                replay: false,
                ..*request
            }
            .steps_without_approval()
        ),
    };
    let tag = if request.replay {
        "[executor:dry-run replay]"
    } else {
        "[executor:dry-run]"
    };
    format!(
        "{tag} rule={} severity={:?} source={} state={:?}: {what}; {check}",
        p.rule, p.severity, p.source, request.safety_state
    )
}

impl<W: Write> Executor for LoggingExecutor<W> {
    fn submit(&mut self, request: &ExecutionRequest<'_>) {
        let _ = writeln!(self.out, "{}", describe(request));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::{Deviation, Severity};
    use robodr_responder::{
        plan_stateless, Connectivity, ControlMode, MissionPhase, PlatformFamily, ResponsePolicy,
    };

    fn ctx(locked: bool) -> OperationalContext {
        OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: Morphology::WheeledMobile,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: locked,
        }
    }

    #[test]
    fn logging_executor_describes_without_acting() {
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.oem_validated = true;
        pol.morphology = Morphology::WheeledMobile;
        let c = ctx(true);
        let dev = Deviation::new("robot.x", Severity::High, "d");
        let plan = plan_stateless(&pol, &dev, "s", SafetyState::MovingSlow, &c);
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::of(&plan),
            safety_state: SafetyState::MovingSlow,
            context: &c,
            evidence: &[],
            finding_id: None,
            replay: false,
        };
        assert_eq!(req.disposition, Disposition::Eligible);
        assert_eq!(
            req.steps_without_approval(),
            vec![Step::Restrict, Step::LimitMotion]
        );
        let mut ex = LoggingExecutor::new(Vec::new());
        ex.submit(&req);
        let line = String::from_utf8(ex.into_inner()).unwrap();
        assert!(
            line.contains("would request [Restrict, LimitMotion]"),
            "{line}"
        );
        assert!(line.contains("invariants ok"));

        // Re-check against a different (engaged) safety state fails, and
        // then nothing is offered.
        let bad = ExecutionRequest {
            safety_state: SafetyState::EStopActive,
            ..req
        };
        assert!(bad.recheck().is_err());
        assert!(bad.steps_without_approval().is_empty());
        assert!(describe(&bad).contains("INVARIANT VIOLATION"));
    }

    #[test]
    fn observe_only_offers_nothing() {
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.morphology = Morphology::WheeledMobile;
        let c = ctx(false);
        let dev = Deviation::new("robot.x", Severity::Critical, "d");
        let plan = plan_stateless(&pol, &dev, "s", SafetyState::MovingFast, &c);
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::of(&plan),
            safety_state: SafetyState::MovingFast,
            context: &c,
            evidence: &[],
            finding_id: None,
            replay: false,
        };
        assert_eq!(req.disposition, Disposition::ObserveOnly);
        assert!(req.steps_without_approval().is_empty());
        assert!(describe(&req).contains("observe only"));
        NoopExecutor.submit(&req);
    }

    fn eligible_plan(c: &OperationalContext) -> ResponsePlan {
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.oem_validated = true;
        pol.morphology = Morphology::WheeledMobile;
        let dev = Deviation::new("robot.x", Severity::High, "d");
        plan_stateless(&pol, &dev, "s", SafetyState::MovingSlow, c)
    }

    #[test]
    fn replay_requests_offer_nothing() {
        let c = ctx(true);
        let plan = eligible_plan(&c);
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::of(&plan),
            safety_state: SafetyState::MovingSlow,
            context: &c,
            evidence: &[],
            finding_id: None,
            replay: true,
        };
        assert_eq!(req.disposition, Disposition::Eligible);
        assert!(req.recheck().is_ok());
        assert!(req.steps_without_approval().is_empty());
        let line = describe(&req);
        assert!(line.starts_with("[executor:dry-run replay]"), "{line}");
        assert!(
            line.contains("would request [Restrict, LimitMotion]"),
            "{line}"
        );
    }

    #[test]
    fn mislabelled_disposition_offers_nothing() {
        let c = ctx(true);
        let mut plan = eligible_plan(&c);
        // The plan needs a human, but the request claims it is eligible.
        plan.requires_human_approval = true;
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::Eligible,
            safety_state: SafetyState::MovingSlow,
            context: &c,
            evidence: &[],
            finding_id: None,
            replay: false,
        };
        assert!(req.steps_without_approval().is_empty());
    }

    #[test]
    fn changed_or_engaged_current_state_offers_nothing() {
        let c = ctx(true);
        let plan = eligible_plan(&c);
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::of(&plan),
            safety_state: SafetyState::MovingSlow,
            context: &c,
            evidence: &[],
            finding_id: None,
            replay: false,
        };
        assert!(!req
            .steps_without_approval_at(SafetyState::MovingSlow)
            .is_empty());
        for s in SafetyState::ALL {
            if s != SafetyState::MovingSlow {
                assert!(req.steps_without_approval_at(s).is_empty(), "{s:?}");
            }
        }
        // Even a plan made for an engaged state offers nothing.
        let engaged = ExecutionRequest {
            safety_state: SafetyState::EStopActive,
            ..req
        };
        assert!(engaged
            .steps_without_approval_at(SafetyState::EStopActive)
            .is_empty());
    }

    #[test]
    fn plan_vocabulary_never_exceeds_a_safe_state_request() {
        // The executor seam can only carry requests: every step a plan can
        // hold is at most `RequestSafeState`, and no step resets, overrides
        // or actuates.
        let c = ctx(true);
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.oem_validated = true;
        pol.morphology = Morphology::WheeledMobile;
        for sev in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            for s in SafetyState::ALL {
                let dev = Deviation::new("robot.x", sev, "d");
                let plan = plan_stateless(&pol, &dev, "s", s, &c);
                assert!(plan.max_step <= Step::RequestSafeState);
                if s.safety_system_engaged() {
                    assert_eq!(plan.steps(), vec![Step::Record], "{s:?}");
                }
            }
        }
    }

    #[test]
    fn executor_compares_its_own_morphology() {
        // M4: the plan and its request context say wheeled; an executor
        // whose own policy says humanoid is offered nothing and its
        // re-check fails, whatever the plan claims about itself.
        let c = ctx(true);
        let plan = eligible_plan(&c);
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::of(&plan),
            safety_state: SafetyState::MovingSlow,
            context: &c,
            evidence: &[],
            finding_id: None,
            replay: false,
        };
        assert_eq!(
            req.steps_without_approval_for(SafetyState::MovingSlow, Morphology::WheeledMobile),
            vec![Step::Restrict, Step::LimitMotion]
        );
        assert_eq!(req.recheck_for(Morphology::WheeledMobile), Ok(()));
        for own in [
            Morphology::Humanoid,
            Morphology::Quadruped,
            Morphology::Unspecified,
        ] {
            assert_eq!(req.recheck_for(own), Err(Violation::MorphologyMismatch));
            assert!(req
                .steps_without_approval_for(SafetyState::MovingSlow, own)
                .is_empty());
        }
        // A plan relabelled as humanoid under a wheeled context is refused too.
        let mut relabelled = plan.clone();
        relabelled.morphology = Morphology::Humanoid;
        let req = ExecutionRequest {
            plan: &relabelled,
            ..req
        };
        assert!(req.recheck().is_err());
        assert!(req
            .steps_without_approval_for(SafetyState::MovingSlow, Morphology::Humanoid)
            .is_empty());
    }
}
