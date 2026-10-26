//! The executor's own decision (pure: no I/O). Every order is checked here
//! twice: [`precheck`] with everything known when it arrives, and
//! [`recheck_safety`] with the platform's **current** safety state,
//! obtained immediately before `nft -f` (executor rule 3 / 4 of
//! `robodr_agent::executor`).
//!
//! Before [`precheck`] the engine establishes `human_approved` itself
//! ([`crate::soc::verify`], trust boundary M1): a control-plane order is
//! approved only when the SOC's signed request verifies with the
//! executor's own keys and matches the order; a planner order never is.
//! Here `human_approved` is that verified flag.
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
//!    (`safety_system_engaged`), and the state was known
//!    (`safety_state_unavailable` for `unknown`);
//! 8. `restrict_motion` is advisory in v1 (the executor does not drive the
//!    motion firewall gateway, a separate unit): recorded,
//!    nothing applied (outcome `advisory`);
//! 9. the target is one executor v1 can act on: a participant by GUID
//!    prefix for `quarantine_node` (`unsupported_target` for a node name or
//!    a process);
//! 10. with the site option `require_approval_for_all_containment`, every
//!     containment needs a human's approval on every morphology
//!     (`needs_approval`); otherwise, on a robot that falls when
//!     de-energised (humanoid, unspecified) the
//!     action must be in the policy's `fall_safe_restrict` (`fall_hazard`)
//!     and approved by a human (`needs_approval`); on a robot that needs
//!     active balance (quadruped too) a quarantine needs a human
//!     (`needs_approval`);
//! 11. the target is not on the motion control path (`motion_path`) unless
//!     the policy lists the target class in `fall_safe_restrict` and the
//!     entry is not `low_level` (a `low_level` entry is never cut): its GUID
//!     prefix is not a non-cuttable entry's, and no non-cuttable entry
//!     names an interface without a `cidr` (nothing can be proven outside
//!     it). A quarantine acts only on locators it can prove lie outside
//!     every non-cuttable entry (outside its `cidr`) **and** in scope
//!     (review F4: inside a `network.quarantine.cidrs` entry, on one of the
//!     robot's DDS ports, not loopback, one address family). Review of the
//!     F3 fix (H2b): a locator failing either check is **left out** (listed
//!     in the plan, the `applied` event and the answer's note, nothing
//!     rendered for it) instead of refusing the whole order, so one bad
//!     locator in the rogue's own SPDP cannot make it unquarantinable. Still
//!     refused: an order whose every locator is on the motion control path
//!     (`motion_path`: the participant may be on it); an empty
//!     `network.quarantine.cidrs` (`locator_out_of_scope`); and, unless
//!     agentd vouched for a GUID-prefix-only quarantine (`guid_only`: the
//!     participant was seen and is not one of the robot's own), an order
//!     with no locator left (`locator_out_of_scope` when it had some,
//!     `locators_required` when it had none). The non-cuttable entries are
//!     frozen into the quarantine and rendered as accepts **before** its
//!     drops, so a quarantine (its GUID-prefix drop included) cannot act
//!     inside a low-level network even when traffic there carries the
//!     quarantined GUID prefix;
//! 12. `isolate_network` needs a configured management channel
//!     (`no_management_channel`), so isolation can never cut the SOC off;
//! 13. the TTL is within `1..=ttl.max_s` (`ttl_out_of_range`).
//!
//! [`recheck_safety`]: the current state must be known (not `unknown`) and
//! fresh (`safety_state_unavailable`, `safety_state_stale`), the safety system
//! not engaged (`safety_system_engaged`) and the state equal to the one the
//! order was judged in (`safety_state_changed`: the action must be judged
//! again, never reused).

use robodr_responder::{
    ActionId, GaExecution, Morphology, ResponsePolicy, RestrictTarget, SafetyState,
};
use serde::{Deserialize, Serialize};

use std::net::IpAddr;

use crate::config::{AllowEntry, ProtectedEntry, Resolved};
use crate::net::{GuidPrefix, Iface, IpNet};
use crate::order::{ExcludedLocator, Locator, Order, Target};

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
    /// A quarantine without the participant's SPDP unicast locators.
    pub const LOCATORS_REQUIRED: &str = "locators_required";
    /// The operator removed table `inet robodr`: nothing is executed until
    /// `robodr-executor rearm`.
    pub const OPERATOR_DISABLED: &str = "operator_disabled";
    /// The configuration or response policy could not be re-read.
    pub const CONFIG_UNAVAILABLE: &str = "config_unavailable";
    // --- Trust boundary (M1, `crate::soc`) ---------------------------------
    /// A control-plane order without a SOC request, or one whose Ed25519
    /// signature does not verify with the executor's own SOC keys for its
    /// own robot id (unknown key, no key configured, malformed request).
    pub const SOC_SIGNATURE_INVALID: &str = "soc_signature_invalid";
    /// The SOC request's timestamp is outside the executor's window, or
    /// fenced (its replay store could not be trusted at start).
    pub const SOC_REQUEST_STALE: &str = "soc_request_stale";
    /// The SOC request's (key, nonce) was already presented (persisted
    /// across restarts).
    pub const SOC_NONCE_REPLAYED: &str = "soc_nonce_replayed";
    /// The replay store is full of live pairs or could not record the pair.
    pub const SOC_REPLAY_STORE_UNAVAILABLE: &str = "soc_replay_store_unavailable";
    /// The order's id, action, target, TTL or origin differ from the signed
    /// request (or the request is not an action request to this robot).
    pub const ORDER_MISMATCH: &str = "order_mismatch";
    /// The approval evidence the contract requires is missing from the
    /// signed body, or a planner order claims a human approval.
    pub const APPROVAL_MISSING: &str = "approval_missing";
    // --- Review of M1 (F4, F9) ----------------------------------------------
    /// A quarantine locator outside `network.quarantine` (its CIDRs, the
    /// robot's DDS ports, one address family), or no quarantinable network
    /// configured.
    pub const LOCATOR_OUT_OF_SCOPE: &str = "locator_out_of_scope";
    /// The SOC key configuration cannot be trusted: a key file unreadable
    /// or refused, or a SOC key equal to one of the robot's own keys. Every
    /// control-plane order is refused until it is fixed (integrity first:
    /// one bad file never silently drops to fewer keys).
    pub const SOC_KEYS_UNAVAILABLE: &str = "soc_keys_unavailable";
    /// An action held after a reboot was approved with a SOC key that is no
    /// longer configured: not re-armed.
    pub const APPROVAL_KEY_REMOVED: &str = "approval_key_removed";

    /// Every code, for mapping a wire string back to a static one.
    pub const ALL: [&str; 30] = [
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
        LOCATORS_REQUIRED,
        OPERATOR_DISABLED,
        CONFIG_UNAVAILABLE,
        SOC_SIGNATURE_INVALID,
        SOC_REQUEST_STALE,
        SOC_NONCE_REPLAYED,
        SOC_REPLAY_STORE_UNAVAILABLE,
        ORDER_MISMATCH,
        APPROVAL_MISSING,
        LOCATOR_OUT_OF_SCOPE,
        SOC_KEYS_UNAVAILABLE,
        APPROVAL_KEY_REMOVED,
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
    /// DDS discovery kept open (absent in journals of executor v1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoverySpec>,
}

/// The robot's DDS discovery kept open during an isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverySpec {
    /// SPDP multicast groups.
    pub groups: Vec<IpAddr>,
    /// Their UDP destination ports (RTPS port map of the domains).
    pub ports: Vec<u16>,
    /// Interfaces of the protected and control-bus entries; empty = any
    /// interface (some entry names an address only).
    #[serde(default)]
    pub interfaces: Vec<Iface>,
}

/// The rule inputs of a participant quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineSpec {
    pub guid_prefix: GuidPrefix,
    #[serde(default)]
    pub locators: Vec<Locator>,
    /// Locators of the order left out (by agentd, or here: out of scope,
    /// loopback, another address family, inside a motion-path entry it
    /// may not cut), with the reason. Nothing is rendered for them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<ExcludedLocator>,
    /// The motion control path entries this quarantine may not cut,
    /// rendered as accepts before any quarantine drop.
    #[serde(default)]
    pub protected: Vec<ProtectedEntry>,
}

/// What an accepted order does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    Isolate(IsolationSpec),
    Quarantine(QuarantineSpec),
    /// Black-box mark and bundle (done by agentd, which owns the black box).
    Evidence,
    /// Recorded only (v1 `restrict_motion`: the executor does not drive the
    /// motion firewall gateway).
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

/// Why `l` cannot be proven to lie outside the non-cuttable entry `e`, if
/// it cannot: inside its `cidr`, or `e` names an interface and no address
/// (any locator may be behind it).
fn locator_unproven(e: &ProtectedEntry, l: &Locator) -> Option<String> {
    match (&e.cidr, &e.interface) {
        (Some(c), _) if c.contains(l.ip) => Some(format!("locator {} is inside {c}", l.ip)),
        (Some(_), _) => None,
        (None, Some(i)) => Some(format!(
            "the entry names interface {} and no address: no locator can be proven outside it",
            i.as_str()
        )),
        // Not a valid entry (config validation refuses it): never proven.
        (None, None) => Some("the entry names no address".into()),
    }
}

/// Review finding F4: a quarantine acts only on locators in a configured
/// quarantinable network (`network.quarantine.cidrs`), on one of the
/// robot's DDS ports, never loopback, and all in one address family. A
/// forged SPDP locator can then at most name a DDS endpoint of a network
/// the site declared quarantinable, never an arbitrary UDP service (a DNS
/// server, the SOC's syslog) that the quarantine's locator drops would
/// blackhole. Review of the F3 fix (H2b): a locator outside that scope is
/// **left out** (listed with its reason, nothing rendered for it) instead
/// of refusing the whole order, so one bad locator in the rogue's own SPDP
/// cannot make it unquarantinable. An empty scope still refuses.
fn locators_in_scope(
    q: &mut QuarantineSpec,
    net: &crate::config::NetworkSection,
) -> Result<(), Refusal> {
    let scope = &net.quarantine;
    if scope.cidrs.is_empty() {
        return Err(Refusal::new(
            codes::LOCATOR_OUT_OF_SCOPE,
            format!(
                "participant {}: network.quarantine.cidrs is empty: the executor cannot tie any \
                 SPDP locator to a quarantinable participant; not quarantined",
                q.guid_prefix
            ),
        ));
    }
    let ports = scope.ports(&net.discovery);
    let mut keep = Vec::new();
    for l in std::mem::take(&mut q.locators) {
        let why = if l.ip.is_loopback() {
            Some("loopback address".to_string())
        } else if !scope.cidrs.iter().any(|c| c.contains(l.ip)) {
            Some("outside every network.quarantine.cidrs entry".to_string())
        } else if !ports.iter().any(|r| r.contains(l.port)) {
            Some("not one of the robot's DDS ports".to_string())
        } else {
            None
        };
        match why {
            Some(reason) => exclude(q, l, reason),
            None => keep.push(l),
        }
    }
    // One address family: IPv4 if any is left.
    let v4 = keep.iter().any(|l| l.ip.is_ipv4());
    for l in keep {
        if l.ip.is_ipv4() == v4 {
            q.locators.push(l);
        } else {
            exclude(
                q,
                l,
                "address family differs from the other locators".into(),
            );
        }
    }
    Ok(())
}

fn exclude(q: &mut QuarantineSpec, l: Locator, reason: String) {
    if q.excluded.len() < crate::order::MAX_EXCLUDED * 2 {
        q.excluded.push(ExcludedLocator {
            ip: l.ip,
            port: l.port,
            reason: format!("executor: {reason}"),
        });
    }
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
    if order.judged_state == SafetyState::Unknown {
        return Err(Refusal::new(
            codes::SAFETY_STATE_UNAVAILABLE,
            "the action was judged without a known safety state: nothing is executed",
        ));
    }
    if order.action == ActionId::RestrictMotion {
        return Ok(Planned {
            effect: Effect::Advisory {
                note: "restrict_motion is advisory in executor v1: the executor does not drive \
                       the motion firewall gateway (robodr-firewall-gw, a separate unit with its \
                       own static envelope), so the request is recorded and nothing is changed \
                       on the robot"
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
                guid_only,
                excluded,
            },
        ) => Some((
            QuarantineSpec {
                guid_prefix: *guid_prefix,
                locators: {
                    let mut l = locators.clone();
                    l.sort();
                    l.dedup();
                    l
                },
                excluded: excluded
                    .iter()
                    .take(crate::order::MAX_EXCLUDED)
                    .map(|x| ExcludedLocator {
                        reason: format!("agentd: {}", x.reason),
                        ..x.clone()
                    })
                    .collect(),
                protected: Vec::new(),
            },
            *guid_only,
        )),
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
    if cfg.config.require_approval_for_all_containment && !order.human_approved {
        return Err(Refusal::new(
            codes::NEEDS_APPROVAL,
            format!(
                "this site requires a human's approval for every containment \
                 (require_approval_for_all_containment): {} from the on-robot planner is not \
                 executed",
                order.action.as_str()
            ),
        ));
    }
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
        Some((mut q, guid_only)) => {
            let describe = |i: usize, e: &ProtectedEntry| {
                format!(
                    "network.motion_control_path[{i}]{}{}",
                    if e.low_level { ", low_level" } else { "" },
                    e.note
                        .as_deref()
                        .map(|n| format!(": {n}"))
                        .unwrap_or_default()
                )
            };
            let keep: Vec<(usize, &ProtectedEntry)> = net
                .motion_control_path
                .iter()
                .enumerate()
                .filter(|(_, e)| !cuttable(e, policy, class))
                .collect();
            for (i, e) in &keep {
                if e.guid_prefix == Some(q.guid_prefix) {
                    return Err(Refusal::new(
                        codes::MOTION_PATH,
                        format!(
                            "participant {} is on the motion control path ({}): never \
                             quarantined here",
                            q.guid_prefix,
                            describe(*i, e)
                        ),
                    ));
                }
            }
            // An entry that names an interface and no address: no locator
            // (and no GUID-prefix drop) can be proven outside it. (An order
            // with nothing to act on at all is `locators_required` below.)
            let anything = !q.locators.is_empty() || guid_only;
            for (i, e) in &keep {
                if e.cidr.is_none() && anything {
                    let why = match &e.interface {
                        Some(i) => format!(
                            "the entry names interface {} and no address: no locator can be \
                             proven outside it",
                            i.as_str()
                        ),
                        None => "the entry names no address".to_string(),
                    };
                    return Err(Refusal::new(
                        codes::MOTION_PATH,
                        format!(
                            "participant {} may be on the motion control path ({}): {why}; \
                             never quarantined here",
                            q.guid_prefix,
                            describe(*i, e)
                        ),
                    ));
                }
            }
            // Review of the F3 fix (H2b): a locator inside an entry it may
            // not cut is left out (never acted on) instead of refusing the
            // whole order when the participant also has locators outside;
            // the GUID-prefix drop is rendered after that entry's accepts,
            // so it cannot act inside it either.
            let offered = q.locators.len();
            let mut outside = Vec::new();
            let mut on_path: Option<String> = None;
            for l in std::mem::take(&mut q.locators) {
                match keep.iter().find_map(|(i, e)| {
                    locator_unproven(e, &l).map(|why| format!("{why} ({})", describe(*i, e)))
                }) {
                    Some(why) => {
                        on_path.get_or_insert_with(|| why.clone());
                        exclude(&mut q, l, format!("motion control path: {why}"));
                    }
                    None => outside.push(l),
                }
            }
            q.locators = outside;
            // Every locator it offered is on the motion control path: it may
            // be a motion-path participant itself. Refused (last line).
            if let (Some(why), 0) = (&on_path, q.locators.len()) {
                if offered > 0 {
                    return Err(Refusal::new(
                        codes::MOTION_PATH,
                        format!(
                            "participant {} may be on the motion control path: {why}; never \
                             quarantined here",
                            q.guid_prefix
                        ),
                    ));
                }
            }
            // F4: the locators come from SPDP (unauthenticated): only those a
            // quarantine may act on at all are kept.
            let before_scope = q.locators.len();
            locators_in_scope(&mut q, net)?;
            if q.locators.is_empty() && !guid_only {
                let left_out = if q.excluded.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; left out: {}",
                        q.excluded
                            .iter()
                            .map(|x| format!("{}:{} ({})", x.ip, x.port, x.reason))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                let (code, what) = if before_scope > 0 {
                    (
                        codes::LOCATOR_OUT_OF_SCOPE,
                        "none of its locators is one a quarantine may act on (network.quarantine)",
                    )
                } else {
                    (
                        codes::LOCATORS_REQUIRED,
                        "the order carries none of its SPDP unicast locators",
                    )
                };
                return Err(Refusal::new(
                    code,
                    format!(
                        "participant {}: {what}, and agentd did not vouch for a \
                         GUID-prefix-only quarantine (the prefix is unknown to it, or one of the \
                         robot's own: profiled, pinned or contested): the executor quarantines \
                         only a participant it can prove is outside the motion control path \
                         (GUID prefixes change on restart and can be forged){left_out}",
                        q.guid_prefix
                    ),
                ));
            }
            q.protected = keep.into_iter().map(|(_, e)| e.clone()).collect();
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
            let protected: Vec<ProtectedEntry> = net
                .motion_control_path
                .iter()
                .filter(|e| !cuttable(e, policy, class))
                .cloned()
                .collect();
            let d = &net.discovery;
            let discovery = (!d.multicast_groups.is_empty()).then(|| {
                // The interfaces that carry the protected and control-bus
                // entries; any interface when one of them names none.
                let mut ifs: Vec<Iface> = Vec::new();
                let mut any = false;
                let buses: &[AllowEntry] = if net.control_buses.exempt {
                    &net.control_buses.entries
                } else {
                    &[]
                };
                let named = protected
                    .iter()
                    .map(|e| &e.interface)
                    .chain(buses.iter().map(|e| &e.interface));
                for i in named {
                    match i {
                        Some(i) => ifs.push(i.clone()),
                        None => any = true,
                    }
                }
                if any {
                    ifs.clear();
                }
                ifs.sort();
                ifs.dedup();
                let mut groups = d.multicast_groups.clone();
                groups.sort();
                groups.dedup();
                DiscoverySpec {
                    groups,
                    ports: d.ports(),
                    interfaces: ifs,
                }
            });
            Effect::Isolate(IsolationSpec {
                allow,
                protected,
                discovery,
            })
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
    if c.state == SafetyState::Unknown {
        return Err(Refusal::new(
            codes::SAFETY_STATE_UNAVAILABLE,
            "the platform reports its safety state as unknown: nothing applied",
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

/// The safety check before an action held across a reboot is installed
/// again: the current state must be known, fresh and not engaged (it need
/// not equal the state the order was judged in before the reboot).
pub fn recheck_rearm(current: Result<Current, String>, max_age_ms: u64) -> Result<(), Refusal> {
    let c = current.map_err(|e| {
        Refusal::new(
            codes::SAFETY_STATE_UNAVAILABLE,
            format!("the current safety state could not be read ({e})"),
        )
    })?;
    if c.age_ms > max_age_ms {
        return Err(Refusal::new(
            codes::SAFETY_STATE_STALE,
            format!(
                "the current safety state is {} ms old (limit {max_age_ms} ms)",
                c.age_ms
            ),
        ));
    }
    if c.state.safety_system_engaged() {
        return Err(Refusal::new(
            codes::SAFETY_SYSTEM_ENGAGED,
            format!("the safety system is engaged now ({:?})", c.state),
        ));
    }
    if c.state == SafetyState::Unknown {
        return Err(Refusal::new(
            codes::SAFETY_STATE_UNAVAILABLE,
            "the platform reports its safety state as unknown",
        ));
    }
    Ok(())
}

/// The prefix of a locator as a host prefix (for rendering).
pub fn locator_net(l: &Locator) -> IpNet {
    IpNet::host(l.ip)
}
