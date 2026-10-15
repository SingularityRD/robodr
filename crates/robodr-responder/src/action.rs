//! The response ladder, the actions it is made of, and the plan the responder
//! returns.
//!
//! Every action here is a **request** to some other component (black box,
//! DDS firewall, Motion Firewall, mission executive, safety controller). This
//! crate executes nothing. The vocabulary is closed on purpose: there is no
//! variant for actuation, for cutting power or motors, for killing a process
//! while the robot moves, or for clearing an e-stop, so a policy or a bug
//! cannot express them.

use std::fmt;

use robodr_events::Severity;
use serde::{Deserialize, Serialize};

use crate::state::{PlatformFamily, SafetyState};

/// One rung of the Cyber-Jidoka ladder. Ordered: `Record < Restrict <
/// LimitMotion < SafePause < RequestSafeState`. `RequestSafeState` is the top:
/// nothing beyond it exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// 1. Record evidence to the black box and alert the console.
    Record,
    /// 2. Restrict a network link, DDS participant or process.
    Restrict,
    /// 3. Ask the Motion Firewall to lower the speed/workspace envelope.
    LimitMotion,
    /// 4. Ask the mission executive to pause at a safe point.
    SafePause,
    /// 5. Ask the safety controller for its protective safe state.
    RequestSafeState,
}

impl Step {
    pub const ALL: [Step; 5] = [
        Step::Record,
        Step::Restrict,
        Step::LimitMotion,
        Step::SafePause,
        Step::RequestSafeState,
    ];

    /// 1-based rung number.
    pub fn rung(self) -> u8 {
        self as u8 + 1
    }

    /// The step `n` rungs higher, saturating at `RequestSafeState`.
    pub fn raised(self, n: u8) -> Step {
        let idx = (self as usize).saturating_add(n as usize).min(4);
        Step::ALL[idx]
    }

    /// Steps that change how (or whether) the robot moves.
    pub fn is_motion_affecting(self) -> bool {
        self >= Step::LimitMotion
    }
}

/// What a `Restrict` step targets. Expressed as a request to the platform's
/// enforcement points; nothing is restricted by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestrictTarget {
    /// Cut the robot's external links; the fleet/control link stays open.
    Network,
    /// Deny the offending DDS participant / ROS 2 node.
    Participant,
    /// Quarantine the offending process (cgroup freeze / LSM deny).
    Process,
}

impl RestrictTarget {
    pub const ALL: [RestrictTarget; 3] = [
        RestrictTarget::Network,
        RestrictTarget::Participant,
        RestrictTarget::Process,
    ];
}

/// A platform's safe behaviour, as *requested* from the component that owns it
/// (mission executive, autopilot, safety controller). Platform-specific safe
/// states are data: the policy names one; [`SafeBehaviour::allowed_for`]
/// encodes which are physically sensible per platform family.
///
/// There is deliberately no "cut motors", "remove power" or IEC 60204-1
/// stop category 0 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeBehaviour {
    /// Ground vehicle: decelerate along the path to standstill, brakes held.
    ControlledStop,
    /// Drone: hold position / loiter (requested to the autopilot).
    Hold,
    /// Drone: return to launch (requested to the autopilot).
    ReturnToLaunch,
    /// Arm: protective stop, IEC 60204-1 category 2 (controlled stop, power
    /// maintained to the drives).
    ProtectiveStopCategory2,
    /// Whatever the platform's integrator configured as its safe behaviour.
    PlatformDefined,
}

impl SafeBehaviour {
    pub const ALL: [SafeBehaviour; 5] = [
        SafeBehaviour::ControlledStop,
        SafeBehaviour::Hold,
        SafeBehaviour::ReturnToLaunch,
        SafeBehaviour::ProtectiveStopCategory2,
        SafeBehaviour::PlatformDefined,
    ];

    /// Is this behaviour physically sensible for the platform family?
    ///
    /// * UGV / AMR: controlled stop.
    /// * Drone: hold/loiter or RTL; a drone in flight is never asked to "stop".
    /// * Arm: protective stop category 2.
    /// * Other: only the platform-defined behaviour.
    ///
    /// `PlatformDefined` is allowed everywhere: the platform owns its meaning.
    pub fn allowed_for(self, platform: PlatformFamily) -> bool {
        use PlatformFamily as P;
        use SafeBehaviour as B;
        matches!(
            (platform, self),
            (_, B::PlatformDefined)
                | (P::Ugv | P::Amr, B::ControlledStop)
                | (P::Drone, B::Hold | B::ReturnToLaunch)
                | (P::Arm, B::ProtectiveStopCategory2)
        )
    }
}

/// One concrete action of a plan. Ordered within a plan by ladder step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum ResponseAction {
    /// Record evidence and alert. Always safe, always first.
    Record,
    /// Restrict `target`. `terminate_process` may only be true for a
    /// `Process` target while the robot is [`SafetyState::Idle`] and the policy
    /// allows it; otherwise a process is only quarantined.
    Restrict {
        target: RestrictTarget,
        terminate_process: bool,
    },
    /// Scale the Motion Firewall's speed/workspace envelope by `factor`
    /// (`0 < factor <= 1`; never 0 — a stop is `SafePause`).
    LimitMotion { factor: f64 },
    /// Pause the mission at a safe point using `behaviour`.
    SafePause { behaviour: SafeBehaviour },
    /// Request the safety controller's protective safe state. The safety
    /// controller decides; an operator restarts.
    RequestSafeState { behaviour: SafeBehaviour },
}

impl ResponseAction {
    /// The ladder step this action belongs to.
    pub fn step(&self) -> Step {
        match self {
            ResponseAction::Record => Step::Record,
            ResponseAction::Restrict { .. } => Step::Restrict,
            ResponseAction::LimitMotion { .. } => Step::LimitMotion,
            ResponseAction::SafePause { .. } => Step::SafePause,
            ResponseAction::RequestSafeState { .. } => Step::RequestSafeState,
        }
    }
}

/// Why the planner chose (or capped) what it did. Structured so the console
/// and the evidence chain can render and query it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Reason {
    /// The severity x safety-state matrix cell.
    Matrix {
        severity: Severity,
        state: SafetyState,
        step: Step,
    },
    /// A per-rule override clamped the matrix step into `[min, max]`.
    RuleOverride {
        rule: String,
        min: Step,
        max: Step,
        result: Step,
    },
    /// Repeated deviations from the same source raised the step.
    Escalated { level: u8, result: Step },
    /// The step was held at a previously planned level for this source
    /// (no automatic de-escalation).
    Held { step: Step },
    /// E-stop / safe state already active: only Record.
    SafetySystemHasAuthority,
    /// The context's platform does not match the policy's; only Record.
    PlatformMismatch {
        policy: PlatformFamily,
        context: PlatformFamily,
    },
    /// Safety state unknown: motion-affecting steps need a human.
    UnknownSafetyState,
    /// A human is commanding motion: motion-affecting steps are proposals.
    HumanInCommand,
    /// Take-off / landing: interrupting motion is itself a hazard.
    TransientPhase,
    /// Step is above the policy's `auto_max_step`.
    AboveAutoCeiling { auto_max_step: Step },
    /// Approval is needed but no operator link is available right now.
    ApprovalChannelUnavailable,
    /// The configured limit-motion factor is not in (0, 1]; dropped.
    InvalidLimitFactor,
    /// A configured safe behaviour is not valid for the platform; dropped.
    InvalidSafeBehaviour { behaviour: SafeBehaviour },
    /// The deviation itself was raised in observe mode
    /// (`robodr_events::Mode::Observe`): informational, never acted upon.
    ObserveModeDeviation,
    /// Profile not locked: observe mode.
    ObserveModeProfileUnlocked,
    /// Policy not OEM-validated: observe mode.
    ObserveModePolicyNotValidated,
    /// An equal-or-higher auto-executable plan was issued for the same
    /// (source, rule) within the re-issue interval: reduced to Record.
    RateLimited { since_ms: u64 },
    /// An equal-or-higher motion-affecting step, from a plan of equal-or-higher
    /// severity, was issued robot-wide within the re-issue interval and is
    /// still in force (plans never relax). This plan's redundant
    /// motion-affecting actions were dropped; its Record/Restrict actions,
    /// which target its own source, are kept.
    MotionAlreadyRequested { step: Step, since_ms: u64 },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Matrix {
                severity,
                state,
                step,
            } => write!(f, "matrix[{severity:?}][{state:?}] = {step:?}"),
            Reason::RuleOverride {
                rule,
                min,
                max,
                result,
            } => write!(f, "override {rule} [{min:?}..{max:?}] -> {result:?}"),
            Reason::Escalated { level, result } => {
                write!(f, "escalated +{level} -> {result:?}")
            }
            Reason::Held { step } => write!(f, "held at {step:?}"),
            Reason::SafetySystemHasAuthority => {
                write!(f, "safety system engaged: record only")
            }
            Reason::PlatformMismatch { policy, context } => {
                write!(
                    f,
                    "platform mismatch (policy {policy:?}, robot {context:?}): record only"
                )
            }
            Reason::UnknownSafetyState => write!(f, "safety state unknown: approval required"),
            Reason::HumanInCommand => write!(f, "human in command: approval required"),
            Reason::TransientPhase => write!(f, "take-off/landing: approval required"),
            Reason::AboveAutoCeiling { auto_max_step } => {
                write!(f, "above auto ceiling {auto_max_step:?}: approval required")
            }
            Reason::ApprovalChannelUnavailable => {
                write!(f, "approval channel unavailable: only record executes")
            }
            Reason::InvalidLimitFactor => write!(f, "invalid limit-motion factor: dropped"),
            Reason::InvalidSafeBehaviour { behaviour } => {
                write!(
                    f,
                    "safe behaviour {behaviour:?} invalid for platform: dropped"
                )
            }
            Reason::ObserveModeDeviation => write!(f, "observe mode (deviation is observe-only)"),
            Reason::ObserveModeProfileUnlocked => write!(f, "observe mode (profile unlocked)"),
            Reason::ObserveModePolicyNotValidated => {
                write!(f, "observe mode (policy not OEM-validated)")
            }
            Reason::RateLimited { since_ms } => {
                write!(
                    f,
                    "rate limited ({since_ms} ms since last issue for this source and rule)"
                )
            }
            Reason::MotionAlreadyRequested { step, since_ms } => write!(
                f,
                "{step:?} already requested robot-wide {since_ms} ms ago: motion part dropped"
            ),
        }
    }
}

/// Structured rationale: the ordered list of reasons that produced the plan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rationale {
    pub reasons: Vec<Reason>,
}

impl Rationale {
    pub fn push(&mut self, r: Reason) {
        self.reasons.push(r);
    }

    pub fn contains(&self, pred: impl Fn(&Reason) -> bool) -> bool {
        self.reasons.iter().any(pred)
    }
}

impl fmt::Display for Rationale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, r) in self.reasons.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{r}")?;
        }
        Ok(())
    }
}

/// The responder's output. A plan is a list of *requests*, ordered by ladder
/// step, plus the conditions under which they may be carried out.
///
/// Execution contract for whoever consumes it:
/// * `observe_only` → only `Record` is in `actions`; `would_have` holds the
///   plan that enforcement mode would have produced. Always the case for a
///   deviation raised in observe mode.
/// * `requires_human_approval` → only `Record` may be executed before a human
///   approves; everything else waits.
/// * Plans are cumulative and never relax anything: a later, lower plan does
///   not lift an earlier restriction. Lifting is an operator action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlan {
    pub rule: String,
    pub severity: Severity,
    /// The deviation's source key (participant GUID, process, link...).
    pub source: String,
    pub safety_state: SafetyState,
    /// Highest step present in `actions`.
    pub max_step: Step,
    pub actions: Vec<ResponseAction>,
    pub requires_human_approval: bool,
    pub observe_only: bool,
    /// Set when the rate limiter reduced this plan to Record because the same
    /// (source, rule) got an equal-or-higher auto-executable plan within the
    /// re-issue interval. Never set because of another source's activity.
    pub suppressed: bool,
    /// In observe mode: what enforcement mode would have done.
    pub would_have: Option<Box<ResponsePlan>>,
    pub rationale: Rationale,
}

impl ResponsePlan {
    /// The steps present, in order.
    pub fn steps(&self) -> Vec<Step> {
        let mut v: Vec<Step> = self.actions.iter().map(|a| a.step()).collect();
        v.dedup();
        v
    }

    /// Human-readable one-line rationale.
    pub fn rationale_text(&self) -> String {
        self.rationale.to_string()
    }
}
