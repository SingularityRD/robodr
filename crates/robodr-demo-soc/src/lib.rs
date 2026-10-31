//! # robodr-demo-soc
//!
//! A demo SOC for RoboDR proofs of concept (gap T28): what a customer sees
//! receive, verify and show the findings a robot sends, in one binary.
//!
//! * `POST /robot-edr/v2/ingest`: the `robodr.ingest` v1 API
//!   (`docs/contracts/robodr.ingest-api.md`), answered by the **reference
//!   consumer** shared with `robodr-export`'s tests
//!   (`crates/robodr-export/tests/common/ingest.rs`, compiled in, not
//!   copied): content type, limits, header syntax, batch Ed25519 signature,
//!   replay, per-line validation, robot binding, per-finding signature,
//!   dedup. `robodr-uplink` talks to it unchanged.
//! * Accepted findings go to an append-only NDJSON store with their arrival
//!   time and verification status ([`store`]).
//! * `GET /` is a viewer (attacker-controlled text is only ever set as
//!   `textContent`, the page has a strict CSP); `GET /api/findings` and
//!   `GET /api/metrics` (counts, **time to SOC** percentiles: arrival minus
//!   the finding's own detection time `ocsf.time`, T64) are JSON.
//!
//! Demo only: one process, unbounded in-memory replay state, plain HTTP,
//! and a test-grade ingest consumer compiled in with the panic lints
//! relaxed. Keep it on loopback or an isolated lab network, never exposed
//! further (README.md). `robodr-uplink` sends plain HTTP only to a
//! loopback address. Not a production SOC.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::todo,
        clippy::unimplemented
    )
)]

/// The reference consumer of the ingest contract, shared with
/// `robodr-export`'s tests (test-grade code: lints relaxed here only).
#[path = "../../robodr-export/tests/common/ingest.rs"]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unreachable
)]
pub mod ingest;

pub mod config;
pub mod http;
pub mod store;
pub mod viewer;
