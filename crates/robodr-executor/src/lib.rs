//! RoboDR executor v1: carries out the **reversible** catalog actions on
//! the robot host, in a separate process that holds `CAP_NET_ADMIN` and
//! nothing else, and never anything that may de-energise an actuator.
//!
//! | Action | Adapter | What it does | Revert | TTL |
//! |---|---|---|---|---|
//! | `isolate_network` | [`nft`] | drops all traffic except loopback, the management / uplink allow-list, the control buses (configurable) and the motion control path | exact inverse (re-render without it) | always (default `ttl.default_s`) |
//! | `quarantine_node` | [`nft`] | drops RTPS from the participant's GUID prefix (raw payload match) and UDP to / from its SPDP locators | exact inverse | always |
//! | `record_evidence` | [`evidence`] (in agentd) | signed black-box mark naming the evidence bundle | not applicable | none |
//! | `restrict_motion` | none in v1 | recorded as advisory to the Motion Firewall (no gateway yet) | — | — |
//! | `safe_pause`, `request_safe_state`, `rollback_config` | none | refused (`not_executor_action`) | — | — |
//!
//! Every adapter follows precheck ([`decision::precheck`], against the
//! executor's **own** response policy and configuration) → safety re-check
//! immediately before apply ([`decision::recheck_safety`]) → apply → verify
//! (read back) → revert (exact inverse, idempotent) → TTL auto-revert with
//! a persisted deadline ([`journal`]) and reconciliation at restart
//! ([`engine::Engine::open`]).
//!
//! agentd talks to the executor over a unix socket with an authenticated
//! protocol ([`proto`], [`client`], [`server`]); agentd itself holds no
//! `CAP_NET_ADMIN`.
//!
//! See `README.md` for the safety argument and the limits.

pub mod client;
pub mod config;
pub mod decision;
pub mod engine;
pub mod evidence;
#[cfg(feature = "fault-injection")]
pub mod fault;
pub mod journal;
pub mod net;
pub mod nft;
pub mod order;
pub mod proto;
pub mod server;

pub use config::{ExecutorConfig, Resolved};
pub use decision::{precheck, recheck_safety, Current, Effect, Planned, Refusal};
pub use engine::{Engine, Outcome, SafetyOracle, Status};
pub use order::{Locator, Order, Origin, Target};

/// `/proc/sys/kernel/random/boot_id` (empty when unreadable: then every
/// start counts as a new boot and active actions are re-applied).
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| {
            s.trim()
                .chars()
                .filter(|c| c.is_ascii_hexdigit() || *c == '-')
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
