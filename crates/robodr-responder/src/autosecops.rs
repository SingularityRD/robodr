//! Mapping of ladder actions to AutoSecOps (AI SOC) action classes.
//!
//! Names follow the design document's "Robot yanıt aksiyonları" table
//! (`robot_restrict_motion`, `robot_quarantine_node`, `robot_isolate_network`,
//! `robot_safe_pause`, `robot_request_safe_state`). The design doc has no
//! class for evidence capture; `robot_record_evidence` is **proposed** here
//! and flagged with `in_design_doc = false`.
//!
//! All classes belong to the `robotics` autonomy category, which must never be
//! autonomous: `autonomous_eligible` is `false` for every class and no class
//! may be added to AutoSecOps' `AUTONOMOUS_ELIGIBLE` list. Fleet-level actions
//! always need an analyst; pause and safe-state need two people.

use serde::Serialize;

use crate::action::{ResponseAction, RestrictTarget};

/// AutoSecOps autonomy category for every robot action.
pub const ROBOTICS_CATEGORY: &str = "robotics";

/// Approval tier ("Kademe" column of the design doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// One analyst approves.
    Analyst,
    /// Two people approve (four-eyes).
    TwoPerson,
}

/// Reversibility ("Geri alınabilir" column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// No effect on the robot to reverse (evidence capture).
    NotApplicable,
    Reversible,
    /// Reversible and automatically time-bounded.
    TimeBounded,
    /// Not reversible by the system: an operator restarts.
    OperatorRestart,
}

/// One AutoSecOps action class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionClass {
    pub name: &'static str,
    pub category: &'static str,
    pub approval: Approval,
    /// Always false for robotics; present so the contract is explicit.
    pub autonomous_eligible: bool,
    pub reversibility: Reversibility,
    /// False for classes proposed here but not (yet) in the design doc.
    pub in_design_doc: bool,
}

const fn class(
    name: &'static str,
    approval: Approval,
    reversibility: Reversibility,
    in_design_doc: bool,
) -> ActionClass {
    ActionClass {
        name,
        category: ROBOTICS_CATEGORY,
        approval,
        autonomous_eligible: false,
        reversibility,
        in_design_doc,
    }
}

/// Every class this crate can emit, for registration with AutoSecOps.
pub const ALL_CLASSES: [ActionClass; 6] = [
    class(
        "robot_record_evidence",
        Approval::Analyst,
        Reversibility::NotApplicable,
        false,
    ),
    class(
        "robot_isolate_network",
        Approval::Analyst,
        Reversibility::TimeBounded,
        true,
    ),
    class(
        "robot_quarantine_node",
        Approval::Analyst,
        Reversibility::Reversible,
        true,
    ),
    class(
        "robot_restrict_motion",
        Approval::Analyst,
        Reversibility::TimeBounded,
        true,
    ),
    class(
        "robot_safe_pause",
        Approval::TwoPerson,
        Reversibility::Reversible,
        true,
    ),
    class(
        "robot_request_safe_state",
        Approval::TwoPerson,
        Reversibility::OperatorRestart,
        true,
    ),
];

/// The AutoSecOps action class for a ladder action.
pub fn action_class(action: &ResponseAction) -> ActionClass {
    let idx = match action {
        ResponseAction::Record => 0,
        ResponseAction::Restrict {
            target: RestrictTarget::Network,
            ..
        } => 1,
        ResponseAction::Restrict {
            target: RestrictTarget::Participant | RestrictTarget::Process,
            ..
        } => 2,
        ResponseAction::LimitMotion { .. } => 3,
        ResponseAction::SafePause { .. } => 4,
        ResponseAction::RequestSafeState { .. } => 5,
    };
    ALL_CLASSES[idx]
}
