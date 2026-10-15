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
//!    `request_safe_state`, and the platform's safety controller decides.

use std::io::Write;

use robodr_ocsf::BlackBoxRef;
use robodr_responder::{
    check_invariants, OperationalContext, ResponsePlan, SafetyState, Step, Violation,
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
}

impl ExecutionRequest<'_> {
    /// The mandatory re-check (see module docs).
    pub fn recheck(&self) -> Result<(), Violation> {
        check_invariants(self.plan, self.safety_state, self.context)
    }

    /// Steps an executor could request right now without a human, after a
    /// successful [`recheck`](Self::recheck). Empty unless the disposition is
    /// [`Disposition::Eligible`]; `Record` is excluded (already done).
    pub fn steps_without_approval(&self) -> Vec<Step> {
        if self.disposition != Disposition::Eligible || self.recheck().is_err() {
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
        Disposition::Eligible => format!(
            "would request {:?} (no approval needed)",
            request.steps_without_approval()
        ),
    };
    format!(
        "[executor:dry-run] rule={} severity={:?} source={} state={:?}: {what}; {check}",
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
        let pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
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
        };
        assert_eq!(req.disposition, Disposition::ObserveOnly);
        assert!(req.steps_without_approval().is_empty());
        assert!(describe(&req).contains("observe only"));
        NoopExecutor.submit(&req);
    }
}
