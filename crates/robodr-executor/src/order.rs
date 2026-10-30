//! What agentd asks the executor to do: one [`Order`] per catalog action.
//!
//! An order carries the action, its target and the situation agentd judged
//! it in (safety state, operational context, the plan's morphology, whether
//! a human approved it). The executor re-checks all of it against its own
//! policy and the *current* safety state ([`crate::decision`]); nothing in
//! an order widens what the executor may do.

use std::net::IpAddr;

use robodr_responder::{ActionId, Morphology, OperationalContext, SafetyState};
use serde::{Deserialize, Serialize};

use crate::net::{clip, id_ok, GuidPrefix};

/// Most locators per participant target.
pub const MAX_LOCATORS: usize = 16;
/// Most left-out locators listed per participant target.
pub const MAX_EXCLUDED: usize = 32;
/// Most source addresses per participant target (review R3-1).
pub const MAX_ADDRESSES: usize = 16;
/// Most left-out source addresses listed per participant target.
pub const MAX_EXCLUDED_ADDRESSES: usize = 16;
/// Longest free-text field of an origin.
pub const MAX_TEXT: usize = 200;

/// A unicast locator of a DDS participant (from its SPDP announcement).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub ip: IpAddr,
    pub port: u16,
}

/// A locator left out of a quarantine, and why.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedLocator {
    pub ip: IpAddr,
    pub port: u16,
    pub reason: String,
}

/// A source address left out of a quarantine, and why (review R3-1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedAddress {
    pub ip: IpAddr,
    pub reason: String,
}

/// What an action acts on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// No target (`isolate_network`, `record_evidence`, `restrict_motion`).
    #[default]
    None,
    /// A DDS participant: its GUID prefix and, when known, the unicast
    /// locators it announced in SPDP.
    Participant {
        guid_prefix: GuidPrefix,
        #[serde(default)]
        locators: Vec<Locator>,
        /// agentd vouches that the participant was seen and is not one of
        /// the robot's own (profiled, pinned or contested): when no locator
        /// is left, the executor may quarantine it by its GUID-prefix
        /// payload drop alone (which matches RTPS sent by that prefix only).
        /// `false`: no locator left is `locators_required`, as before.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        guid_only: bool,
        /// Announced locators agentd left out, and why (evidence only; the
        /// executor never acts on them).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        excluded: Vec<ExcludedLocator>,
        /// Review R3-1: the source addresses agentd saw the participant
        /// send from and vouches for (not loopback, not this host's, not
        /// pinned to another participant, not a profiled participant's
        /// host). The executor drops all UDP from them to the robot's DDS
        /// ports, and to their DDS ports, whatever the source port (a DDS
        /// stack such as Fast DDS sends from ephemeral ports, which a
        /// locator rule never matches).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        addresses: Vec<IpAddr>,
        /// Observed source addresses agentd left out, and why (evidence
        /// only; the executor never acts on them).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        excluded_addresses: Vec<ExcludedAddress>,
        /// agentd forgot some of the addresses the participant was seen
        /// sending from (more than it keeps per participant): the
        /// quarantine can never be `full`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        evidence_truncated: bool,
    },
    /// A ROS 2 node by name (not resolvable by executor v1: refused).
    Node { name: String },
    /// Motion actions (Sprint 8, `crate::motion`): the restriction's
    /// parameters (the control plane's caps, or the planner's
    /// `limit_motion` factor) or the rollback's target. A control-plane
    /// order's must equal the signed body's parameters (`order_mismatch`).
    Motion(crate::motion::MotionRequest),
    /// A process (never executed by executor v1: refused).
    Process { name: String },
}

/// Who asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Origin {
    /// A SOC request that passed the control plane's judgment (signed by
    /// `key_id`, approved on the SOC side).
    ControlPlane {
        key_id: String,
        requested_by: String,
    },
    /// An on-robot response plan's executable step (no human).
    Planner {
        rule: String,
        #[serde(default)]
        finding_id: Option<String>,
    },
}

/// One action for the executor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    /// Idempotency key (`[A-Za-z0-9._:-]{1,128}`): the control plane's
    /// `request_id`, or `plan:<hash>` for a planner step.
    pub id: String,
    pub action: ActionId,
    #[serde(default)]
    pub target: Target,
    /// Requested TTL; `None` = the executor's default. Every applied rule
    /// set has a deadline.
    #[serde(default)]
    pub ttl_s: Option<u64>,
    /// Safety state the action was judged in.
    pub judged_state: SafetyState,
    /// Operational context it was judged in.
    pub context: OperationalContext,
    /// Morphology of the plan / judgment (from agentd's policy).
    pub plan_morphology: Morphology,
    /// A human approved this action (SOC approval).
    pub human_approved: bool,
    /// The order comes from a replay of recorded or synthetic input.
    #[serde(default)]
    pub replay: bool,
    pub origin: Origin,
    /// Wall clock (Unix ms) when agentd issued it.
    pub issued_ms: u64,
    /// The SOC's signed request this order stands for (control-plane
    /// orders only; executor M1). The executor accepts `human_approved`
    /// only when it verifies this request itself ([`crate::soc::verify`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soc: Option<Box<crate::soc::SocRequest>>,
}

fn is_broadcast(a: IpAddr) -> bool {
    matches!(a, IpAddr::V4(v) if v.is_broadcast())
}

fn text_ok(s: &str) -> bool {
    s.chars().count() <= MAX_TEXT && !s.chars().any(char::is_control)
}

impl Order {
    /// Structural validation (what any order must look like). Safety rules
    /// are in [`crate::decision`].
    pub fn validate(&self) -> Result<(), String> {
        if !id_ok(&self.id) {
            return Err(format!(
                "order id {:?} is not [A-Za-z0-9._:-]{{1,128}}",
                clip(&self.id)
            ));
        }
        match &self.target {
            Target::None => {}
            Target::Participant {
                locators,
                excluded,
                addresses,
                excluded_addresses,
                ..
            } => {
                if addresses.len() > MAX_ADDRESSES
                    || excluded_addresses.len() > MAX_EXCLUDED_ADDRESSES
                    || excluded_addresses
                        .iter()
                        .any(|x| x.reason.is_empty() || !text_ok(&x.reason))
                {
                    return Err(format!(
                        "more than {MAX_ADDRESSES} addresses or {MAX_EXCLUDED_ADDRESSES} excluded \
                         addresses, or a reason empty, too long or with control characters"
                    ));
                }
                if let Some(a) = addresses
                    .iter()
                    .find(|a| a.is_unspecified() || a.is_multicast() || is_broadcast(**a))
                {
                    return Err(format!(
                        "address {a} is not a unicast address (quarantine would match unrelated \
                         traffic)"
                    ));
                }
                if locators.len() > MAX_LOCATORS {
                    return Err(format!("more than {MAX_LOCATORS} locators"));
                }
                if excluded.len() > MAX_EXCLUDED
                    || excluded
                        .iter()
                        .any(|x| x.reason.is_empty() || !text_ok(&x.reason))
                {
                    return Err(format!(
                        "more than {MAX_EXCLUDED} excluded locators, or a reason empty, too long \
                         or with control characters"
                    ));
                }
                for l in locators {
                    if l.port == 0 {
                        return Err("locator port 0".into());
                    }
                    if l.ip.is_unspecified() || l.ip.is_multicast() {
                        return Err(format!(
                            "locator {} is not a unicast address (quarantine would match \
                             unrelated traffic)",
                            l.ip
                        ));
                    }
                }
            }
            Target::Node { name } | Target::Process { name } => {
                if name.is_empty() || !text_ok(name) {
                    return Err("target name empty, too long or with control characters".into());
                }
            }
            Target::Motion(m) => {
                let bad_num = [m.factor, m.max_linear_speed, m.max_joint_speed]
                    .iter()
                    .flatten()
                    .any(|x| !x.is_finite());
                let bad_text = [&m.workspace_zone, &m.config, &m.to_version]
                    .iter()
                    .any(|t| t.as_deref().is_some_and(|t| t.is_empty() || !text_ok(t)));
                if bad_num || bad_text {
                    return Err("motion parameters not finite, or text empty / invalid".into());
                }
            }
        }
        match &self.origin {
            Origin::ControlPlane {
                key_id,
                requested_by,
            } => {
                if !text_ok(key_id) || !text_ok(requested_by) {
                    return Err("origin text too long or with control characters".into());
                }
            }
            Origin::Planner { rule, finding_id } => {
                if !text_ok(rule) || finding_id.as_deref().is_some_and(|f| !text_ok(f)) {
                    return Err("origin text too long or with control characters".into());
                }
                if self.soc.is_some() {
                    return Err("a planner order carries no SOC request".into());
                }
            }
        }
        Ok(())
    }

    /// What makes two orders with one id the same order.
    pub fn digest(&self) -> String {
        let canon =
            serde_json::to_string(&(self.action, &self.target, self.ttl_s)).unwrap_or_default();
        robodr_blackbox::crypto::to_hex(&robodr_blackbox::crypto::sha256(canon.as_bytes()))
    }
}
