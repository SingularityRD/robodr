//! Cyber-Jidoka responder (pure): graded, safety-aware response planning.
//! Never overrides the platform safety system.
//!
//! Given a [`robodr_events::Deviation`], the robot's [`SafetyState`] and its
//! [`OperationalContext`], the responder decides a [`ResponsePlan`]: an
//! ordered, cumulative climb up the five-step ladder
//!
//! 1. **Record** — evidence to the black box, alert to the console;
//! 2. **Restrict** — network link / DDS participant / process (requested from
//!    the enforcement points);
//! 3. **Limit motion** — Motion Firewall scales the envelope;
//! 4. **Safe pause** — mission paused at a safe point, using the platform's
//!    own safe behaviour (UGV controlled stop, drone hold/RTL, arm protective
//!    stop cat. 2 — data in the policy, never "cut motors");
//! 5. **Request safe state** — the safety controller is *asked*; it decides.
//!
//! This crate is a planning library: it performs no I/O and executes nothing.
//! Every action is a request for another component to carry out.
//!
//! # Invariants (enforced in code regardless of policy)
//!
//! * Nothing beyond `RequestSafeState` is expressible: no actuation, no power
//!   or motor cut, no e-stop override, no killing a process mid-motion
//!   (termination only while `Idle` and only if the policy allows it).
//! * `EStopActive` / `SafeStateActive` → Record only: the safety system has
//!   authority.
//! * `Unknown` safety state, a human in command (teleop/manual) or a transient
//!   phase (take-off/landing) → motion-affecting steps need human approval.
//! * Observe mode (deviation raised in `Mode::Observe`, profile not locked, or
//!   policy not OEM-validated) → Record only, with the would-have plan
//!   attached.
//! * Safe behaviours must be valid for the platform family.
//!
//! The policy is validated at load ([`ResponsePolicy::validate`]) and the
//! plan is re-checked at the end of planning
//! ([`check_invariants_for_deviation`]); a
//! violating plan is replaced by Record + approval, so failure modes only ever
//! make the response *less* active.
//!
//! See `README.md` in this crate for the policy format and what is not yet
//! verified (OEM validation, real platform safe-state interfaces).

pub mod action;
pub mod autosecops;
pub mod escalation;
pub mod planner;
pub mod policy;
pub mod state;

pub use action::{
    Rationale, Reason, ResponseAction, ResponsePlan, RestrictTarget, SafeBehaviour, Step,
};
pub use autosecops::{action_class, ActionClass, Approval, Reversibility};
pub use escalation::Responder;
pub use planner::{check_invariants, check_invariants_for_deviation, plan_stateless, Violation};
pub use policy::{
    EscalationPolicy, Matrix, PolicyError, ResponsePolicy, RuleOverride, SeverityRow,
};
pub use state::{
    Connectivity, ControlMode, MissionPhase, OperationalContext, PlatformFamily, SafetyState,
};

#[cfg(test)]
mod tests;
