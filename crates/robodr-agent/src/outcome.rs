//! What one deviation produced: the plan, how it may be handled, the
//! black-box evidence and the finding.

use robodr_events::Deviation;
use robodr_ocsf::BlackBoxRef;
use robodr_responder::{ResponsePlan, Step};
use serde::Serialize;

use crate::clock::ClockAnomaly;

/// What kind of agent-internal failure an [`AgentFault`] is. Faults are about
/// the agent itself, not the robot, and never reach the responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    /// Monotonic time went backwards (clamped).
    ClockRegression,
    /// Wall time disagreed with monotonic time beyond the tolerance.
    WallClockJump,
    /// A black-box append failed (first failure of an outage).
    EvidenceWriteFailed,
    /// Reopening a failed black box failed.
    EvidenceRecoveryFailed,
    /// The black box accepts records again after an outage; `detail` says
    /// how many appends were lost.
    EvidenceRecovered,
}

/// One agent-internal failure, see [`crate::agent`] ("Failure handling").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentFault {
    pub kind: FaultKind,
    /// Agent time (sanitised) when it was raised.
    pub mono_ns: u64,
    pub wall_ns: u64,
    pub detail: String,
    pub clock: Option<ClockAnomaly>,
    /// The signed `robodr.agent_fault` note, if the black box took it.
    pub record: Option<BlackBoxRef>,
}

/// Which detector raised the deviation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// `robodr_events::profile::Profile::evaluate`.
    Profile,
    /// `robodr_firewall::Firewall` (verdict on a `MotionCommand`).
    Firewall,
    /// `robodr_motion::ConsistencyMonitor` (commands vs feedback).
    MotionMonitor,
    /// A deviation raised outside the agent by the ROS 2 detection pipeline
    /// (`robodr-ros2-pipeline`: profile, binding, protocol and capture
    /// findings), handed in with [`crate::Agent::handle_external`].
    Sensor,
    /// A deviation about the host process itself (input silent, pipeline
    /// lagging, queue overflow, ...), raised by a daemon such as
    /// `robodr-agentd` and handed in with [`crate::Agent::handle_external`].
    /// Always observe-only: it never feeds an action.
    SelfHealth,
}

/// How a plan may be handled downstream. Derived from the plan only; the
/// agent itself executes nothing in any case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Observe mode (profile unlocked, observe-only deviation or policy not
    /// OEM-validated): `Record` only; `plan.would_have` shows enforcement.
    ObserveOnly,
    /// The responder's rate limiter reduced the plan to `Record`.
    Suppressed,
    /// The plan is `Record` only (evidence + alert, already done by the agent).
    RecordOnly,
    /// Steps above `Record` exist but need a human decision first. Only
    /// `Record` may run before approval.
    AwaitingHumanApproval,
    /// Steps above `Record` an executor may request without a human, after
    /// it re-runs `robodr_responder::check_invariants` on the plan.
    Eligible,
}

impl Disposition {
    pub fn of(plan: &ResponsePlan) -> Self {
        if plan.observe_only {
            Disposition::ObserveOnly
        } else if plan.suppressed {
            Disposition::Suppressed
        } else if plan.max_step == Step::Record {
            Disposition::RecordOnly
        } else if plan.requires_human_approval {
            Disposition::AwaitingHumanApproval
        } else {
            Disposition::Eligible
        }
    }

    /// `true` if anything beyond `Record` could ever follow from this plan
    /// (immediately or after approval).
    pub fn is_actionable(self) -> bool {
        matches!(
            self,
            Disposition::AwaitingHumanApproval | Disposition::Eligible
        )
    }
}

/// References into the black box. Every `Some` is a record that was
/// appended (hash-chained and signed) and appears in the finding's
/// `evidence_links`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EvidenceLinks {
    /// The triggering `RobotEvent`.
    pub event: Option<BlackBoxRef>,
    /// The Motion Firewall verdict on the triggering command, if any.
    pub firewall_verdict: Option<BlackBoxRef>,
    /// The `Deviation`.
    pub deviation: Option<BlackBoxRef>,
    /// The `ResponsePlan` (as a note).
    pub plan: Option<BlackBoxRef>,
    /// Appends that failed or were refused (saturation). The outcome and
    /// finding are still produced: losing storage must not hide a detection.
    pub errors: Vec<String>,
}

impl EvidenceLinks {
    pub fn refs(&self) -> Vec<BlackBoxRef> {
        [
            &self.event,
            &self.firewall_verdict,
            &self.deviation,
            &self.plan,
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }
}

/// A validated findings record (`robodr.findings` contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingOutput {
    pub topic: String,
    /// Kafka record key (= finding id).
    pub key: String,
    pub partition: Option<u32>,
    /// Compact, validated finding JSON (the Kafka record value).
    pub value: String,
    pub headers: Vec<(String, String)>,
}

/// Summary of one Motion Firewall verdict, as recorded in the black box.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FirewallVerdictRecord {
    /// Always `robodr.firewall_verdict`.
    pub kind: &'static str,
    pub channel: String,
    pub source_guid: Option<String>,
    /// `passed`, `limited` or `rejected`.
    pub verdict: &'static str,
    /// `RejectReason` (Debug name) for rejections.
    pub reject_reason: Option<String>,
    /// For `limited`: `speed`, `acceleration`, `jerk`.
    pub limit_reasons: Vec<&'static str>,
    /// Observe mode: what enforcement would have done (Debug rendering).
    pub would_have: Option<String>,
    /// Substitute emitted instead of a rejected command (`zero`, `hold_last`).
    pub substitute: Option<&'static str>,
    /// Output the gateway would forward: linear speed norm (twist) or max
    /// |joint speed|. `None` if nothing is forwarded. NaN serialises as null.
    pub output_speed: Option<f64>,
    /// Whether the firewall was enforcing (profile locked, not pass-through).
    pub enforcing: bool,
}

impl FirewallVerdictRecord {
    /// A verdict worth recording on its own: anything but a clean pass.
    pub fn is_notable(&self) -> bool {
        self.verdict != "passed" || self.would_have.is_some()
    }
}

/// The result of handling one deviation.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub detector: Detector,
    /// Escalation key handed to the responder (`participant:<guid prefix>`
    /// or `channel:<name>`).
    pub source: String,
    pub deviation: Deviation,
    pub plan: ResponsePlan,
    pub disposition: Disposition,
    /// Set when the agent's own backstop replaced the responder's plan with
    /// `Record` + approval (never expected; see [`crate::agent`]).
    pub guard_violation: Option<String>,
    pub evidence: EvidenceLinks,
    /// The firewall verdict on the triggering command, if the firewall ran.
    pub firewall: Option<FirewallVerdictRecord>,
    /// The finding, or why it could not be built/validated.
    pub finding: Option<FindingOutput>,
    pub finding_errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::Severity;
    use robodr_responder::{Rationale, ResponseAction, SafetyState};

    fn plan(max: Step, approval: bool, observe: bool, suppressed: bool) -> ResponsePlan {
        ResponsePlan {
            rule: "r".into(),
            severity: Severity::High,
            source: "s".into(),
            safety_state: SafetyState::Idle,
            max_step: max,
            actions: vec![ResponseAction::Record],
            requires_human_approval: approval,
            observe_only: observe,
            suppressed,
            would_have: None,
            morphology: Default::default(),
            advisory: Vec::new(),
            rationale: Rationale::default(),
        }
    }

    #[test]
    fn disposition_precedence() {
        use Disposition::*;
        assert_eq!(
            Disposition::of(&plan(Step::Record, true, true, true)),
            ObserveOnly
        );
        assert_eq!(
            Disposition::of(&plan(Step::Record, false, false, true)),
            Suppressed
        );
        assert_eq!(
            Disposition::of(&plan(Step::Record, true, false, false)),
            RecordOnly
        );
        assert_eq!(
            Disposition::of(&plan(Step::SafePause, true, false, false)),
            AwaitingHumanApproval
        );
        assert_eq!(
            Disposition::of(&plan(Step::Restrict, false, false, false)),
            Eligible
        );
        assert!(Eligible.is_actionable() && AwaitingHumanApproval.is_actionable());
        assert!(!ObserveOnly.is_actionable() && !RecordOnly.is_actionable());
    }

    #[test]
    fn evidence_refs_in_fixed_order() {
        let r = |seq| BlackBoxRef {
            segment: 0,
            seq,
            sha256: "00".repeat(32),
        };
        let e = EvidenceLinks {
            event: Some(r(1)),
            firewall_verdict: None,
            deviation: Some(r(2)),
            plan: Some(r(3)),
            errors: vec![],
        };
        let seqs: Vec<u64> = e.refs().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }
}
