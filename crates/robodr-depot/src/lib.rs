//! # robodr-depot
//!
//! The site depot of RoboDR's secure delivery (`docs/SECURE-DELIVERY.md`
//! §4–§6, §8, Sprints 14a and 14b): the single-box control plane inside
//! the air gap.
//!
//! * [`entry`]: the entry station's scan and signed entry report (§6.1);
//! * [`depot::Depot::import`]: a bundle enters only as the verified copy
//!   of `robodr-release`'s import (§3.5 item 30) and only with a passing
//!   entry report for exactly that bundle; revoked or below-floor RPKs
//!   and chain gaps are refused;
//! * enrolment (§8, [`depot::Depot::enrol_verify`]): EK certificate chain
//!   to a TPM vendor CA the trust file lists, credential activation of the
//!   AK, AK certification of the UWK (bound to the site's policy authority,
//!   erase epoch and lease key) and of the unit identity key, a quote of
//!   the signed policy's PCRs, then the operator quorum;
//! * rollouts ([`depot::Depot::rollout_create`]): lab → canary → ring-n in
//!   order, one deployment per stage, each needing the operator quorum of
//!   its ring; a stage advances only when every unit of it reported its
//!   items installed and healthy after the soak; a failing report beyond
//!   the threshold **halts** the rollout (nothing more is served) until
//!   operators resume it;
//! * per-unit re-wrapping of sealed content keys for enrolled units only
//!   (§7.3; replaces `robodr-seal rewrap` as the depot step);
//! * serving: mutual TLS on the site LAN ([`serve`]; the unit's client key
//!   is its TPM-resident identity key) and per-unit media packs;
//! * site leases (Sprint 14b, [`robodr_seal::lease`]) and an NV-counter
//!   anchor against database rollback ([`db`]).
//!
//! Findings (`robot.depot.*`, contract 2.3) go into the site agentd's
//! spool with `robodr-deliverd`'s writer.

// S10: no unsafe code at all in this crate.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`; non-test code has no
// unwrap / expect / panic!-family call.
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

pub mod cli;
pub mod config;
pub mod db;
pub mod depot;
pub mod entry;
pub mod serve;
pub mod x509;

use std::fmt;

/// Depot finding rule ids (contract 2.3, `catalog_2_3_depot`).
pub mod rules {
    pub const IMPORT_REFUSED: &str = "robot.depot.import_refused";
    pub const ENROLMENT_REFUSED: &str = "robot.depot.enrolment_refused";
    pub const UNIT_ENROLLED: &str = "robot.depot.unit_enrolled";
    pub const ROLLOUT_HALTED: &str = "robot.depot.rollout_halted";
    pub const LOCKED: &str = "robot.depot.locked";
    pub const ALL: [&str; 5] = [
        IMPORT_REFUSED,
        ENROLMENT_REFUSED,
        UNIT_ENROLLED,
        ROLLOUT_HALTED,
        LOCKED,
    ];
}

/// A depot error or refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepotError(pub String);

impl fmt::Display for DepotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DepotError {}

pub(crate) fn err(s: impl Into<String>) -> DepotError {
    DepotError(s.into())
}

/// Unix seconds now (a clock before 1970 is an error, never 0).
pub fn now() -> Result<u64, DepotError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| err("system clock before 1970"))
}

/// 32 random bytes.
pub(crate) fn random32() -> Result<[u8; 32], DepotError> {
    let mut b = [0u8; 32];
    robodr_blackbox::crypto::fill_random(&mut b).map_err(|e| err(format!("randomness: {e}")))?;
    Ok(b)
}
