//! RoboDR executor v1: carries out the **reversible** catalog actions on
//! the robot host, in a separate process that holds `CAP_NET_ADMIN` and
//! nothing else, and never anything that may de-energise an actuator.
//!
//! | Action | Adapter | What it does | Revert | TTL |
//! |---|---|---|---|---|
//! | `isolate_network` | [`nft`] | drops all traffic except loopback, the management / uplink allow-list, the control buses (configurable), the motion control path, the robot's DDS discovery, DHCP, path MTU and IPv6 neighbour discovery | exact inverse (re-render without it) | always (default `ttl.default_s`) |
//! | `quarantine_node` | [`nft`] | drops RTPS from the participant's GUID prefix (raw payload match), UDP to / from the source addresses it was seen sending from on the robot's DDS ports (any source port, review R3-1) and to / from its SPDP locators (addresses or locators required, provably outside the motion control path; that path is accepted before any drop) | exact inverse | always |
//! | `record_evidence` | [`evidence`] (in agentd) | signed black-box mark naming the evidence bundle | not applicable | none |
//! | `restrict_motion` | none in v1 | recorded as advisory (the executor does not drive the separate `robodr-firewall-gw` unit) | — | — |
//! | `safe_pause`, `request_safe_state`, `rollback_config` | none | refused (`not_executor_action`) | — | — |
//!
//! Every adapter follows precheck ([`decision::precheck`], against the
//! executor's **own** response policy and configuration) → safety re-check
//! immediately before apply ([`decision::recheck_safety`]) → apply → verify
//! (read back) → revert (exact inverse, idempotent) → TTL auto-revert with
//! a persisted deadline (CLOCK_BOOTTIME within a boot, [`journal`]) and
//! reconciliation at restart ([`engine::Engine::open`]; after a reboot an
//! action is re-validated and held until a fresh safety check).
//!
//! The executor verifies a SOC approval itself ([`soc`], trust boundary
//! M1): agentd forwards the SOC's signed control-plane request with each
//! order, and `human_approved` holds only when that signature verifies with
//! the executor's own SOC keys and the order is the signed one.
//!
//! agentd talks to the executor over a unix socket with an authenticated
//! protocol ([`proto`], [`client`], [`server`]); agentd itself holds no
//! `CAP_NET_ADMIN`.
//!
//! See `README.md` for the safety argument and the limits.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// executor (systemd restarts it and its ExecStopPost removes the table;
// docs/OPERATIONS.md, "Crashes and restarts"). Non-test code has no
// unwrap / expect / panic!-family call; slice indexing and arithmetic are
// left to review.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

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
pub mod nftmodel;
pub mod order;
pub mod proto;
pub mod server;
pub mod soc;

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
