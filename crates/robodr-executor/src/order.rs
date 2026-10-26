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
/// Longest free-text field of an origin.
pub const MAX_TEXT: usize = 200;

/// A unicast locator of a DDS participant (from its SPDP announcement).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub ip: IpAddr,
    pub port: u16,
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
    },
    /// A ROS 2 node by name (not resolvable by executor v1: refused).
    Node { name: String },
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
            Target::Participant { locators, .. } => {
                if locators.len() > MAX_LOCATORS {
                    return Err(format!("more than {MAX_LOCATORS} locators"));
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
