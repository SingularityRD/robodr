//! The vendor-neutral robot action catalog: the **single** list of
//! containment actions RoboDR knows, shared by the responder (which plans
//! them), the agentd control plane (which accepts requests for them) and any
//! SOC integration (which registers them as approval-gated actions).
//!
//! | Action | Wire name | Step | Reversible | Approval | GA |
//! |---|---|---|---|---|---|
//! | `restrict_motion` | `robot_restrict_motion` | `limit_motion` | yes (time-limited) | single | executed |
//! | `quarantine_node` | `robot_quarantine_node` | `restrict` | yes | single | executed |
//! | `isolate_network` | `robot_isolate_network` | `restrict` | yes (time-limited) | single | executed |
//! | `record_evidence` | `robot_record_evidence` | `record` | yes (no lasting effect) | single | executed |
//! | `safe_pause` | `robot_safe_pause` | `safe_pause` | yes | two-person | platform adapter only |
//! | `request_safe_state` | `robot_request_safe_state` | `request_safe_state` | no | two-person | plan only |
//! | `rollback_config` | `robot_rollback_config` | `restrict` | no | two-person | plan only |
//!
//! Rules that hold for every entry (tested):
//!
//! * **Never autonomous.** No robot action may be carried out without a
//!   human approving it on the SOC side; `autonomous` is `false` for every
//!   entry and there is no way to express anything else. (The on-robot
//!   responder may still *plan* actions automatically up to its policy's
//!   `auto_max_step`; that plan is a request to on-robot enforcement points,
//!   not a SOC action.)
//! * **Wire names** are `robot_<name>`. They are unchanged from the earlier
//!   integration so stored approvals and registrations keep working; a
//!   consumer that wants a namespace-free name uses [`ActionSpec::name`].
//! * **GA execution** ([`GaExecution`]): only the reversible actions run in
//!   GA; `safe_pause` runs only through a platform adapter (Nav2,
//!   ros2_control, autopilot hold) under an OEM-validated policy; the
//!   irreversible `request_safe_state` and `rollback_config` are plan-only.
//! * **May de-energise** ([`ActionSpec::may_de_energise`]): `safe_pause` and
//!   `request_safe_state` may be implemented by the platform by damping or
//!   de-energising actuators. On a platform that falls when it loses
//!   actuation (a humanoid) they are never executable, only advisory (see
//!   [`crate::Morphology`]).

use serde::{Deserialize, Serialize};

use crate::action::{ResponseAction, RestrictTarget, Step};

/// Every robot containment action. Serialised as its [`ActionId::as_str`]
/// name (`restrict_motion`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionId {
    RestrictMotion,
    QuarantineNode,
    IsolateNetwork,
    RecordEvidence,
    SafePause,
    RequestSafeState,
    RollbackConfig,
}

/// Approval needed on the SOC side before the action may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// One authorised person approves.
    Single,
    /// Two different people approve (four-eyes); the requester is not one
    /// of them.
    TwoPerson,
}

/// How the action is carried out in the GA release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GaExecution {
    /// Executed by RoboDR's own executor (network, DDS, firewall gateway,
    /// black box), verified and revertible.
    Executor,
    /// Executed only through a platform adapter (Nav2, ros2_control,
    /// autopilot), and only under an OEM-validated response policy.
    PlatformAdapter,
    /// Planned, judged and recorded; never executed in GA.
    PlanOnly,
}

/// One catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionSpec {
    pub id: ActionId,
    /// Namespace-free name, e.g. `restrict_motion`.
    pub name: &'static str,
    /// Name on the wire to a SOC, e.g. `robot_restrict_motion`.
    pub wire_name: &'static str,
    /// The Cyber-Jidoka ladder step the action stands on.
    pub step: Step,
    /// Can be undone by a later request (a safe state needs an operator
    /// restart; a rollback is not undone).
    pub reversible: bool,
    /// Needs a TTL and lapses on its own.
    pub time_limited: bool,
    pub approval: Approval,
    /// Always `false`: robot actions are never autonomous.
    pub autonomous: bool,
    /// Executed in GA at all (by RoboDR's executor or a platform adapter).
    pub executable_in_ga: bool,
    /// How it is executed in GA.
    pub ga_execution: GaExecution,
    /// The platform may implement it by damping / de-energising actuators.
    pub may_de_energise: bool,
}

#[allow(clippy::too_many_arguments)]
const fn spec(
    id: ActionId,
    name: &'static str,
    wire_name: &'static str,
    step: Step,
    reversible: bool,
    time_limited: bool,
    approval: Approval,
    ga_execution: GaExecution,
    may_de_energise: bool,
) -> ActionSpec {
    ActionSpec {
        id,
        name,
        wire_name,
        step,
        reversible,
        time_limited,
        approval,
        autonomous: false,
        executable_in_ga: !matches!(ga_execution, GaExecution::PlanOnly),
        ga_execution,
        may_de_energise,
    }
}

/// The catalog, in [`ActionId::ALL`] order.
pub const CATALOG: [ActionSpec; 7] = [
    spec(
        ActionId::RestrictMotion,
        "restrict_motion",
        "robot_restrict_motion",
        Step::LimitMotion,
        true,
        true,
        Approval::Single,
        GaExecution::Executor,
        false,
    ),
    spec(
        ActionId::QuarantineNode,
        "quarantine_node",
        "robot_quarantine_node",
        Step::Restrict,
        true,
        false,
        Approval::Single,
        GaExecution::Executor,
        false,
    ),
    spec(
        ActionId::IsolateNetwork,
        "isolate_network",
        "robot_isolate_network",
        Step::Restrict,
        true,
        true,
        Approval::Single,
        GaExecution::Executor,
        false,
    ),
    spec(
        ActionId::RecordEvidence,
        "record_evidence",
        "robot_record_evidence",
        Step::Record,
        true,
        false,
        Approval::Single,
        GaExecution::Executor,
        false,
    ),
    spec(
        ActionId::SafePause,
        "safe_pause",
        "robot_safe_pause",
        Step::SafePause,
        true,
        false,
        Approval::TwoPerson,
        GaExecution::PlatformAdapter,
        true,
    ),
    spec(
        ActionId::RequestSafeState,
        "request_safe_state",
        "robot_request_safe_state",
        Step::RequestSafeState,
        false,
        false,
        Approval::TwoPerson,
        GaExecution::PlanOnly,
        true,
    ),
    spec(
        ActionId::RollbackConfig,
        "rollback_config",
        "robot_rollback_config",
        Step::Restrict,
        false,
        false,
        Approval::TwoPerson,
        GaExecution::PlanOnly,
        false,
    ),
];

impl ActionId {
    pub const ALL: [ActionId; 7] = [
        ActionId::RestrictMotion,
        ActionId::QuarantineNode,
        ActionId::IsolateNetwork,
        ActionId::RecordEvidence,
        ActionId::SafePause,
        ActionId::RequestSafeState,
        ActionId::RollbackConfig,
    ];

    /// The catalog entry.
    pub const fn spec(self) -> ActionSpec {
        CATALOG[self as usize]
    }

    /// Namespace-free name, e.g. `restrict_motion`.
    pub const fn as_str(self) -> &'static str {
        self.spec().name
    }

    /// Wire name, e.g. `robot_restrict_motion`.
    pub const fn wire_name(self) -> &'static str {
        self.spec().wire_name
    }

    /// Parse a namespace-free name (`restrict_motion`).
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    /// Parse a wire name (`robot_restrict_motion`).
    pub fn parse_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.wire_name() == s)
    }

    pub const fn step(self) -> Step {
        self.spec().step
    }

    pub const fn reversible(self) -> bool {
        self.spec().reversible
    }

    pub const fn time_limited(self) -> bool {
        self.spec().time_limited
    }

    pub const fn approval(self) -> Approval {
        self.spec().approval
    }

    pub const fn executable_in_ga(self) -> bool {
        self.spec().executable_in_ga
    }

    pub const fn may_de_energise(self) -> bool {
        self.spec().may_de_energise
    }
}

/// The catalog action a planned ladder action corresponds to.
pub fn for_action(action: &ResponseAction) -> ActionId {
    match action {
        ResponseAction::Record => ActionId::RecordEvidence,
        ResponseAction::Restrict {
            target: RestrictTarget::Network,
            ..
        } => ActionId::IsolateNetwork,
        ResponseAction::Restrict {
            target: RestrictTarget::Participant | RestrictTarget::Process,
            ..
        } => ActionId::QuarantineNode,
        ResponseAction::LimitMotion { .. } => ActionId::RestrictMotion,
        ResponseAction::SafePause { .. } => ActionId::SafePause,
        ResponseAction::RequestSafeState { .. } => ActionId::RequestSafeState,
    }
}

/// The catalog entry for a planned ladder action.
pub fn spec_for(action: &ResponseAction) -> ActionSpec {
    for_action(action).spec()
}
