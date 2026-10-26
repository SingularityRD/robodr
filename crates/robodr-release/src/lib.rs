//! # robodr-release
//!
//! The connected-side release tool of RoboDR's secure delivery
//! (`docs/SECURE-DELIVERY.md` §4.1, Sprint 13a): build RPKs from a payload
//! directory, sign RPKs, bundles, trust files and deployments with a key
//! quorum (one `sign` per key holder), assemble chained release bundles
//! with Reed-Solomon parity, verify them anywhere (another host, the entry
//! station) and repair damaged bundles from their parity.
//!
//! Every format decision lives in the pure crate `robodr-pkg`; this crate
//! only reads and writes files ([`fsio`]: no symlinks, exact trees, size
//! caps, atomic outputs) and runs the CLI ([`cli`]).

// S10: no unsafe code at all in this crate.
#![forbid(unsafe_code)]
// Review L3 (S10, R9): release builds use `panic = "abort"`; non-test code
// has no unwrap / expect / panic!-family call.
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
pub mod fsio;
pub mod ops;
