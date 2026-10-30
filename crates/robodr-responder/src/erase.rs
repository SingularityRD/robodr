//! Crypto-erase in the responder's vocabulary (`docs/SECURE-DELIVERY.md`
//! §7.6, Sprint 14b): the **first executed response**.
//!
//! Erase destroys the unit's sealing keys (`robodr-seal`: the TPM erase
//! epoch moves on); it touches no actuator, so it is safe in every
//! safety state as far as the robot's motion goes. It is still graded by
//! the safety state like every other action, because erase also stops the
//! services that run delivered software from the runtime volume and
//! closes that volume (§7.6): **never mid-motion**, unless the platform's
//! own safety system already holds the robot.
//!
//! | safety state | decision |
//! |---|---|
//! | `idle`, `safe_state_active`, `estop_active` | execute |
//! | `moving_slow`, `moving_fast`, `collaborative_human_nearby` | defer (until one of the above) |
//! | `unknown` | defer (the state must be known) |
//!
//! Who may trigger it (§7.6 table): the local triggers the platform wires
//! to the agent (enclosure tamper, repeated attestation failure, repeated
//! failed operator authentication, an expired lease) are planned without a
//! human, like the responder's other on-robot plans up to its ceiling;
//! a signed remote command and an operator erase on the unit are
//! **two-person** ([`EraseTrigger::needs_two_persons`]), the rule of the
//! catalog's irreversible actions. Erase is not in [`crate::CATALOG`]
//! (the SOC / control-plane action set): the control plane does not route
//! it today (§11, open question 7); the unit agent executes it under the
//! executor rules of `robodr_agent::executor` (rules 1-5: re-derive the
//! plan, act on nothing for a replay, re-check the live safety state
//! immediately before acting, journal the intent first, read back the
//! effect).

use serde::{Deserialize, Serialize};

use crate::state::SafetyState;

/// The action's name in plans, evidence and findings.
pub const CRYPTO_ERASE: &str = "crypto_erase";

/// What fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseTrigger {
    /// Enclosure tamper input from the platform (GPIO / bus signal).
    Tamper,
    /// Attestation failed N consecutive boots.
    AttestationFailed,
    /// The site lease expired by more than the grace period.
    LeaseExpired,
    /// Too many failed local operator authentications.
    AuthFailures,
    /// A signed "erase unit" command from the depot or the SOC.
    SignedCommand,
    /// An operator on the unit.
    Operator,
}

impl EraseTrigger {
    pub const ALL: [EraseTrigger; 6] = [
        EraseTrigger::Tamper,
        EraseTrigger::AttestationFailed,
        EraseTrigger::LeaseExpired,
        EraseTrigger::AuthFailures,
        EraseTrigger::SignedCommand,
        EraseTrigger::Operator,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EraseTrigger::Tamper => "tamper",
            EraseTrigger::AttestationFailed => "attestation_failed",
            EraseTrigger::LeaseExpired => "lease_expired",
            EraseTrigger::AuthFailures => "auth_failures",
            EraseTrigger::SignedCommand => "signed_command",
            EraseTrigger::Operator => "operator",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// Triggers a person issues: two people must approve (four-eyes).
    pub fn needs_two_persons(self) -> bool {
        matches!(self, EraseTrigger::SignedCommand | EraseTrigger::Operator)
    }

    /// Triggers the platform raises through the agent's trigger socket.
    pub fn is_platform_input(self) -> bool {
        matches!(
            self,
            EraseTrigger::Tamper | EraseTrigger::AttestationFailed | EraseTrigger::AuthFailures
        )
    }
}

/// What to do now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum EraseDecision {
    Execute,
    /// Wait for a state that allows it; keep the erase pending.
    Defer {
        until: String,
    },
    /// Two different people must approve first.
    AwaitApproval {
        persons: u8,
    },
}

/// The responder's plan for one erase trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasePlan {
    pub action: String,
    pub trigger: EraseTrigger,
    pub safety_state: SafetyState,
    pub decision: EraseDecision,
    pub rationale: String,
}

/// Whether erase may run in `s` (see the module table).
pub fn erase_allowed_in(s: SafetyState) -> bool {
    matches!(
        s,
        SafetyState::Idle | SafetyState::SafeStateActive | SafetyState::EStopActive
    )
}

/// Plan an erase for `trigger` in safety state `state`, with `approvers`
/// distinct people approving (0 for a platform trigger).
pub fn plan_erase(trigger: EraseTrigger, state: SafetyState, approvers: u8) -> ErasePlan {
    let (decision, rationale) = if trigger.needs_two_persons() && approvers < 2 {
        (
            EraseDecision::AwaitApproval { persons: 2 },
            format!(
                "{}: an erase a person orders needs two different approvers",
                trigger.as_str()
            ),
        )
    } else if erase_allowed_in(state) {
        (
            EraseDecision::Execute,
            format!(
                "{state:?}: the robot is idle or its safety system holds it; erase touches no \
                 actuator"
            ),
        )
    } else if state == SafetyState::Unknown {
        (
            EraseDecision::Defer {
                until: "a known safety state of idle, safe_state_active or estop_active".into(),
            },
            "safety state unknown: erase stops services and closes the runtime volume, so the \
             state must be known"
                .into(),
        )
    } else {
        (
            EraseDecision::Defer {
                until: "idle, safe_state_active or estop_active".into(),
            },
            format!("{state:?}: never mid-motion; deferred until the robot is idle"),
        )
    };
    ErasePlan {
        action: CRYPTO_ERASE.into(),
        trigger,
        safety_state: state,
        decision,
        rationale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graded_by_safety_state() {
        for s in SafetyState::ALL {
            let p = plan_erase(EraseTrigger::Tamper, s, 0);
            let exec = p.decision == EraseDecision::Execute;
            assert_eq!(exec, erase_allowed_in(s), "{s:?}");
            assert_eq!(
                exec,
                matches!(
                    s,
                    SafetyState::Idle | SafetyState::SafeStateActive | SafetyState::EStopActive
                )
            );
        }
        assert!(matches!(
            plan_erase(EraseTrigger::Tamper, SafetyState::MovingFast, 0).decision,
            EraseDecision::Defer { .. }
        ));
        assert!(matches!(
            plan_erase(EraseTrigger::Tamper, SafetyState::Unknown, 0).decision,
            EraseDecision::Defer { .. }
        ));
    }

    #[test]
    fn people_need_four_eyes() {
        for t in [EraseTrigger::Operator, EraseTrigger::SignedCommand] {
            assert_eq!(
                plan_erase(t, SafetyState::Idle, 1).decision,
                EraseDecision::AwaitApproval { persons: 2 }
            );
            assert_eq!(
                plan_erase(t, SafetyState::Idle, 2).decision,
                EraseDecision::Execute
            );
            // Approved, but moving: still deferred.
            assert!(matches!(
                plan_erase(t, SafetyState::MovingSlow, 2).decision,
                EraseDecision::Defer { .. }
            ));
        }
        for t in EraseTrigger::ALL {
            assert_eq!(EraseTrigger::parse(t.as_str()), Some(t));
        }
        assert_eq!(EraseTrigger::parse("TAMPER"), None);
    }
}
