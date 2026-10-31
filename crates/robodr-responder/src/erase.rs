//! Crypto-erase in the responder's vocabulary (`docs/SECURE-DELIVERY.md`
//! §7.6, Sprint 14b): the **first executed response**.
//!
//! Erase has two parts, graded separately:
//!
//! * **Key destruction** (the TPM erase epoch moves on, the UWK blobs and
//!   the volume wrap are deleted; without a TPM the runtime volume's
//!   keyslots are wiped). It touches no actuator and stops nothing, so it
//!   runs **at once in every safety state**, `unknown` included: deferring
//!   it would leave the keys an attacker wants usable for as long as the
//!   attacker can keep the robot moving or its safety feed unknown
//!   (unplugged, spoofed).
//! * **Lockdown** of the open runtime volume (stop the services that run
//!   delivered software from it, unmount it, close the mapping). Stopping
//!   services may change what the robot does, so this part is **never
//!   mid-motion**, unless the platform's own safety system already holds
//!   the robot. A lockdown deferred longer than its cap
//!   ([`DEFAULT_MAX_LOCKDOWN_DEFERRAL_S`], [`lockdown_overdue`]) escalates
//!   (a High finding); it still waits for a safe state.
//!
//! | safety state | keys | lockdown |
//! |---|---|---|
//! | `idle`, `safe_state_active`, `estop_active` | destroyed now | now |
//! | `moving_slow`, `moving_fast`, `collaborative_human_nearby` | destroyed now | deferred (until one of the above) |
//! | `unknown` | destroyed now | deferred (the state must be known) |
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

/// Longest a deferred lockdown waits before it escalates (seconds).
pub const DEFAULT_MAX_LOCKDOWN_DEFERRAL_S: u64 = 600;

/// What to do now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum EraseDecision {
    /// Destroy the keys and lock the runtime volume down.
    Execute,
    /// Destroy the keys now; the lockdown waits for a state that allows
    /// it (the erase stays pending until then).
    DestroyKeysDeferLockdown { until: String },
    /// Two different people must approve first.
    AwaitApproval { persons: u8 },
}

impl EraseDecision {
    /// Whether the keys are destroyed now.
    pub fn destroys_keys(&self) -> bool {
        !matches!(self, EraseDecision::AwaitApproval { .. })
    }
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

/// Whether the lockdown part of erase (stop services, unmount, close the
/// runtime volume) may run in `s` (see the module table). Key destruction
/// runs in every state.
pub fn lockdown_allowed_in(s: SafetyState) -> bool {
    matches!(
        s,
        SafetyState::Idle | SafetyState::SafeStateActive | SafetyState::EStopActive
    )
}

/// Whether a lockdown deferred for `deferred_s` seconds is past its cap
/// `max_s` and escalates.
pub fn lockdown_overdue(deferred_s: u64, max_s: u64) -> bool {
    deferred_s >= max_s
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
    } else if lockdown_allowed_in(state) {
        (
            EraseDecision::Execute,
            format!(
                "{state:?}: the robot is idle or its safety system holds it; keys destroyed and \
                 the runtime volume locked down"
            ),
        )
    } else if state == SafetyState::Unknown {
        (
            EraseDecision::DestroyKeysDeferLockdown {
                until: "a known safety state of idle, safe_state_active or estop_active".into(),
            },
            "safety state unknown: the keys are destroyed now (no actuator involved); stopping \
             services and closing the runtime volume waits until the state is known"
                .into(),
        )
    } else {
        (
            EraseDecision::DestroyKeysDeferLockdown {
                until: "idle, safe_state_active or estop_active".into(),
            },
            format!(
                "{state:?}: the keys are destroyed now (no actuator involved); stopping services \
                 is never done mid-motion and waits until the robot is idle"
            ),
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
            assert_eq!(exec, lockdown_allowed_in(s), "{s:?}");
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
            EraseDecision::DestroyKeysDeferLockdown { .. }
        ));
        assert!(matches!(
            plan_erase(EraseTrigger::Tamper, SafetyState::Unknown, 0).decision,
            EraseDecision::DestroyKeysDeferLockdown { .. }
        ));
    }

    /// Review finding (HIGH): `unknown` and every moving state deferred
    /// the whole erase, without limit, so an attacker who keeps the safety
    /// feed unknown (unplugged, spoofed) or the robot moving kept the keys
    /// alive. Key destruction touches no actuator: it is planned in every
    /// state; only the lockdown waits, and escalates past its cap.
    #[test]
    fn keys_are_destroyed_in_every_safety_state() {
        for t in EraseTrigger::ALL {
            for s in SafetyState::ALL {
                let p = plan_erase(t, s, 2);
                assert!(p.decision.destroys_keys(), "{t:?} in {s:?}: {p:?}");
            }
        }
        assert!(!lockdown_overdue(DEFAULT_MAX_LOCKDOWN_DEFERRAL_S - 1, 600));
        assert!(lockdown_overdue(DEFAULT_MAX_LOCKDOWN_DEFERRAL_S, 600));
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
            // Approved, but moving: keys now, the lockdown deferred.
            assert!(matches!(
                plan_erase(t, SafetyState::MovingSlow, 2).decision,
                EraseDecision::DestroyKeysDeferLockdown { .. }
            ));
        }
        for t in EraseTrigger::ALL {
            assert_eq!(EraseTrigger::parse(t.as_str()), Some(t));
        }
        assert_eq!(EraseTrigger::parse("TAMPER"), None);
    }
}
