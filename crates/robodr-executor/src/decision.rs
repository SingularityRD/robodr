//! The executor's own decision (pure: no I/O). Every order is checked here
//! twice: [`precheck`] with everything known when it arrives, and
//! [`recheck_safety`] with the platform's **current** safety state,
//! obtained immediately before `nft -f` (executor rule 3 / 4 of
//! `robodr_agent::executor`).
//!
//! Rules, in order (the first that fails refuses; refusal codes in
//! [`codes`]):
//!
//! 1. the order is well formed;
//! 2. not a replay (`replay`);
//! 3. the catalog action is executed by RoboDR's executor in GA
//!    (`GaExecution::Executor`): `safe_pause` (platform adapter only),
//!    `request_safe_state` and `rollback_config` (plan only) are refused
//!    (`not_executor_action`) — the executor never de-energises anything;
//! 4. `record_evidence` is evidence capture: accepted in every state
//!    (it sends nothing to the platform);
//! 5. the morphology of the order's context **and** of its plan equal the
//!    morphology of the executor's **own** response policy
//!    (`morphology_mismatch`);
//! 6. the policy is OEM-validated and the profile locked (`observe_mode`);
//! 7. the safety system was not engaged when judged
//!    (`safety_system_engaged`);
//! 8. `restrict_motion` is advisory in v1 (no motion gateway yet): recorded,
//!    nothing applied (outcome `advisory`);
//! 9. the target is one executor v1 can act on: a participant by GUID
//!    prefix for `quarantine_node` (`unsupported_target` for a node name or
//!    a process);
//! 10. on a robot that falls when de-energised (humanoid, unspecified) the
//!     action must be in the policy's `fall_safe_restrict` (`fall_hazard`)
//!     and approved by a human (`needs_approval`); on a robot that needs
//!     active balance (quadruped too) a quarantine needs a human
//!     (`needs_approval`);
//! 11. the target is not on the motion control path (`motion_path`) unless
//!     the policy lists the target class in `fall_safe_restrict` and the
//!     entry is not `low_level` (a `low_level` entry is never cut);
//! 12. `isolate_network` needs a configured management channel
//!     (`no_management_channel`), so isolation can never cut the SOC off;
//! 13. the TTL is within `1..=ttl.max_s` (`ttl_out_of_range`).
//!
//! [`recheck_safety`]: the current state must be known and fresh
//! (`safety_state_unavailable`, `safety_state_stale`), the safety system
//! not engaged (`safety_system_engaged`) and the state equal to the one the
//! order was judged in (`safety_state_changed`: the action must be judged
//! again, never reused).

use robodr_responder::{
    ActionId, GaExecution, Morphology, ResponsePolicy, RestrictTarget, SafetyState,
};
use serde::{Deserialize, Serialize};

use crate::config::{AllowEntry, ProtectedEntry, Resolved};
use crate::net::{GuidPrefix, IpNet};
use crate::order::{Locator, Order, Target};

/// Refusal codes (stable, on the wire).
pub mod codes {
    pub const INVALID_ORDER: &str = "invalid_order";
    pub const REPLAY: &str = "replay";
    pub const NOT_EXECUTOR_ACTION: &str = "not_executor_action";
    pub const MORPHOLOGY_MISMATCH: &str = "morphology_mismatch";
    pub const OBSERVE_MODE: &str = "observe_mode";
    pub const SAFETY_SYSTEM_ENGAGED: &str = "safety_system_engaged";
    pub const UNSUPPORTED_TARGET: &str = "unsupported_target";
    pub const FALL_HAZARD: &str = "fall_hazard";
    pub const NEEDS_APPROVAL: &str = "needs_approval";
    pub const MOTION_PATH: &str = "motion_path";
    pub const NO_MANAGEMENT_CHANNEL: &str = "no_management_channel";
    pub const TTL_OUT_OF_RANGE: &str = "ttl_out_of_range";
    pub const SAFETY_STATE_UNAVAILABLE: &str = "safety_state_unavailable";
    pub const SAFETY_STATE_STALE: &str = "safety_state_stale";
    pub const SAFETY_STATE_CHANGED: &str = "safety_state_changed";
    pub const ALREADY_ACTIVE: &str = "already_active";
    pub const ID_CONFLICT: &str = "id_conflict";
    pub const EVIDENCE_ELSEWHERE: &str = "evidence_elsewhere";

    /// Every code, for mapping a wire string back to a static one.
    pub const ALL: [&str; 18] = [
        INVALID_ORDER,
        REPLAY,
        NOT_EXECUTOR_ACTION,
        MORPHOLOGY_MISMATCH,
        OBSERVE_MODE,
        SAFETY_SYSTEM_ENGAGED,
        UNSUPPORTED_TARGET,
        FALL_HAZARD,
        NEEDS_APPROVAL,
        MOTION_PATH,
        NO_MANAGEMENT_CHANNEL,
        TTL_OUT_OF_RANGE,
        SAFETY_STATE_UNAVAILABLE,
        SAFETY_STATE_STALE,
        SAFETY_STATE_CHANGED,
        ALREADY_ACTIVE,
        ID_CONFLICT,
        EVIDENCE_ELSEWHERE,
    ];

    /// The static code for a wire string.
    pub fn intern(s: &str) -> Option<&'static str> {
        ALL.into_iter().find(|c| *c == s)
    }
}

/// Why an order is not executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: String,
    pub reason: String,
}

impl Refusal {
    pub fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
        }
    }
}

/// The rule inputs of an isolation, frozen when it is applied (a later
/// configuration change does not alter an active isolation; restart
/// re-renders exactly these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationSpec {
    /// Management, uplink and (when exempt) control-bus entries.
    pub allow: Vec<AllowEntry>,
    /// Motion control path entries kept open.
    pub protected: Vec<ProtectedEntry>,
}

/// The rule inputs of a participant quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineSpec {
    pub guid_prefix: GuidPrefix,
    #[serde(default)]
    pub locators: Vec<Locator>,
}

/// What an accepted order does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    Isolate(IsolationSpec),
    Quarantine(QuarantineSpec),
    /// Black-box mark and bundle (done by agentd, which owns the black box).
    Evidence,
    /// Recorded only (v1 `restrict_motion`: no motion gateway yet).
    Advisory {
        note: String,
    },
}

/// An order that passed [`precheck`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub effect: Effect,
    /// Seconds; `None` for evidence and advisory.
    pub ttl_s: Option<u64>,
}

fn target_class(action: ActionId) -> Option<RestrictTarget> {
    match action {
        ActionId::IsolateNetwork => Some(RestrictTarget::Network),
        ActionId::QuarantineNode => Some(RestrictTarget::Participant),
        _ => None,
    }
}

fn locator_hits(e: &ProtectedEntry, l: &Locator) -> bool {
    if e.cidr.is_none() && e.interface.is_none() {
        // A GUID-only entry is checked by prefix.
        return false;
    }
    if e.interface.is_some() && e.cidr.is_none() {
        // Interface-only: any locator may be behind it; conservative.
        return true;
    }
    let ip_in = e.cidr.is_none_or(|c| c.contains(l.ip));
    let port_in = e.udp_ports.is_none_or(|r| r.contains(l.port));
    ip_in && port_in
}

/// May this protected entry be cut for `target` under `policy`?
fn cuttable(e: &ProtectedEntry, policy: &ResponsePolicy, target: RestrictTarget) -> bool {
    !e.low_level && policy.fall_safe_restrict.contains(&target)
}

/// Rules 1-13 (see the module docs) against the executor's own policy and
/// configuration. `record_evidence` and `restrict_motion` are planned
/// without a TTL.
pub fn precheck(
    order: &Order,
    policy: &ResponsePolicy,
    cfg: &Resolved,
) -> Result<Planned, Refusal> {
    if let Err(e) = order.validate() {
        return Err(Refusal::new(codes::INVALID_ORDER, e));
    }
    if order.replay {
        return Err(Refusal::new(
            codes::REPLAY,
            "the order comes from a replay of recorded or synthetic input: a replay never \
             reaches a robot",
        ));
    }
    let spec = order.action.spec();
    if spec.ga_execution != GaExecution::Executor || spec.may_de_energise {
        let why = match spec.ga_execution {
            GaExecution::PlatformAdapter => "runs only through an OEM-validated platform adapter",
            GaExecution::PlanOnly => "is plan-only (irreversible)",
            GaExecution::Executor => "may de-energise actuators",
        };
        return Err(Refusal::new(
            codes::NOT_EXECUTOR_ACTION,
            format!(
                "{} {why}: the executor never sends it (it never de-energises anything)",
                order.action.as_str()
            ),
        ));
    }
    if order.action == ActionId::RecordEvidence {
        return Ok(Planned {
            effect: Effect::Evidence,
            ttl_s: None,
        });
    }
    let own = policy.morphology;
    if order.context.morphology != own || order.plan_morphology != own {
        return Err(Refusal::new(
            codes::MORPHOLOGY_MISMATCH,
            format!(
                "the executor's own policy says {}, the order's context {} and its plan {}: \
                 nothing made for another body is executed",
                own.as_str(),
                order.context.morphology.as_str(),
                order.plan_morphology.as_str()
            ),
        ));
    }
    if !policy.oem_validated || !order.context.profile_locked {
        return Err(Refusal::new(
            codes::OBSERVE_MODE,
            "observe mode (policy not OEM-validated or profile not locked): record only",
        ));
    }
    if order.judged_state.safety_system_engaged() {
        return Err(Refusal::new(
            codes::SAFETY_SYSTEM_ENGAGED,
            "the safety system was engaged when the action was judged: it has authority",
        ));
    }
    if order.action == ActionId::RestrictMotion {
        return Ok(Planned {
            effect: Effect::Advisory {
                note: "restrict_motion is advisory in executor v1: no motion firewall gateway \
                       is installed, so the request is recorded and nothing is changed on the \
                       robot"
                    .into(),
            },
            ttl_s: None,
        });
    }
    // From here: isolate_network or quarantine_node.
    let Some(class) = target_class(order.action) else {
        return Err(Refusal::new(
            codes::NOT_EXECUTOR_ACTION,
            format!("{} has no executor adapter", order.action.as_str()),
        ));
    };
    let quarantine = match (&order.action, &order.target) {
        (ActionId::IsolateNetwork, Target::None) => None,
        (ActionId::IsolateNetwork, _) => {
            return Err(Refusal::new(
                codes::INVALID_ORDER,
                "isolate_network takes no target",
            ))
        }
        (
            ActionId::QuarantineNode,
            Target::Participant {
                guid_prefix,
                locators,
            },
        ) => Some(QuarantineSpec {
            guid_prefix: *guid_prefix,
            locators: {
                let mut l = locators.clone();
                l.sort();
                l.dedup();
                l
            },
        }),
        (ActionId::QuarantineNode, Target::Node { .. }) => {
            return Err(Refusal::new(
                codes::UNSUPPORTED_TARGET,
                "executor v1 quarantines a DDS participant by GUID prefix only; a node name \
                 cannot be resolved to one here (send participant_guid)",
            ))
        }
        (ActionId::QuarantineNode, Target::Process { .. }) => {
            return Err(Refusal::new(
                codes::UNSUPPORTED_TARGET,
                "executor v1 never acts on a process (it may be the balance controller)",
            ))
        }
        (ActionId::QuarantineNode, Target::None) => {
            return Err(Refusal::new(
                codes::INVALID_ORDER,
                "quarantine_node needs a participant target",
            ))
        }
        _ => {
            return Err(Refusal::new(
                codes::NOT_EXECUTOR_ACTION,
                "no adapter for this action",
            ))
        }
    };
    let morph: Morphology = own;
    if morph.falls_when_de_energised() {
        if !policy.fall_safe_restrict.contains(&class) {
            return Err(Refusal::new(
                codes::FALL_HAZARD,
                format!(
                    "this robot is configured as {} (it falls when its balance loop loses \
                     input) and the response policy does not list {:?} in fall_safe_restrict: \
                     {} could cut its balance loop",
                    morph.as_str(),
                    class,
                    order.action.as_str()
                ),
            ));
        }
        if !order.human_approved {
            return Err(Refusal::new(
                codes::NEEDS_APPROVAL,
                format!(
                    "on a {} robot every containment needs a human's approval",
                    morph.as_str()
                ),
            ));
        }
    }
    if morph.needs_active_balance() && quarantine.is_some() && !order.human_approved {
        return Err(Refusal::new(
            codes::NEEDS_APPROVAL,
            format!(
                "on a {} robot a quarantine may cut a balance-relevant participant: a human must \
                 approve it",
                morph.as_str()
            ),
        ));
    }
    let net = &cfg.config.network;
    let effect = match quarantine {
        Some(q) => {
            for (i, e) in net.motion_control_path.iter().enumerate() {
                let hit = e.guid_prefix == Some(q.guid_prefix)
                    || q.locators.iter().any(|l| locator_hits(e, l));
                if hit && !cuttable(e, policy, class) {
                    return Err(Refusal::new(
                        codes::MOTION_PATH,
                        format!(
                            "participant {} is on the motion control path \
                             (network.motion_control_path[{i}]{}{}): never quarantined here",
                            q.guid_prefix,
                            if e.low_level { ", low_level" } else { "" },
                            e.note
                                .as_deref()
                                .map(|n| format!(": {n}"))
                                .unwrap_or_default()
                        ),
                    ));
                }
            }
            Effect::Quarantine(q)
        }
        None => {
            if net.management.is_empty() {
                return Err(Refusal::new(
                    codes::NO_MANAGEMENT_CHANNEL,
                    "network.management is empty: isolation would cut the SOC's access to the \
                     robot, so it is not executed",
                ));
            }
            let mut allow: Vec<AllowEntry> = net.management.clone();
            allow.extend(net.uplink.iter().cloned());
            if net.control_buses.exempt {
                allow.extend(net.control_buses.entries.iter().cloned());
            }
            let protected = net
                .motion_control_path
                .iter()
                .filter(|e| !cuttable(e, policy, class))
                .cloned()
                .collect();
            Effect::Isolate(IsolationSpec { allow, protected })
        }
    };
    let ttl = order.ttl_s.unwrap_or(cfg.config.ttl.default_s);
    if ttl == 0 || ttl > cfg.config.ttl.max_s {
        return Err(Refusal::new(
            codes::TTL_OUT_OF_RANGE,
            format!("ttl {ttl} s is outside 1..={} s", cfg.config.ttl.max_s),
        ));
    }
    Ok(Planned {
        effect,
        ttl_s: Some(ttl),
    })
}

/// The platform's current safety state, as read immediately before apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Current {
    pub state: SafetyState,
    /// How old agentd's view of the state is (ms).
    pub age_ms: u64,
}

/// The re-check with the current safety state (see the module docs).
pub fn recheck_safety(
    order: &Order,
    current: Result<Current, String>,
    max_age_ms: u64,
) -> Result<(), Refusal> {
    let c = match current {
        Ok(c) => c,
        Err(e) => {
            return Err(Refusal::new(
                codes::SAFETY_STATE_UNAVAILABLE,
                format!("the current safety state could not be read ({e}): nothing applied"),
            ))
        }
    };
    if c.age_ms > max_age_ms {
        return Err(Refusal::new(
            codes::SAFETY_STATE_STALE,
            format!(
                "the current safety state is {} ms old (limit {max_age_ms} ms): nothing applied",
                c.age_ms
            ),
        ));
    }
    if c.state.safety_system_engaged() {
        return Err(Refusal::new(
            codes::SAFETY_SYSTEM_ENGAGED,
            format!(
                "the safety system is engaged now ({:?}): it has authority, nothing applied",
                c.state
            ),
        ));
    }
    if c.state != order.judged_state {
        return Err(Refusal::new(
            codes::SAFETY_STATE_CHANGED,
            format!(
                "the safety state changed from {:?} (judged) to {:?} (now): the action must be \
                 judged again",
                order.judged_state, c.state
            ),
        ));
    }
    Ok(())
}

/// The prefix of a locator as a host prefix (for rendering).
pub fn locator_net(l: &Locator) -> IpNet {
    IpNet::host(l.ip)
}
