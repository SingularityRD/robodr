//! # robodr-pkg
//!
//! Pure parsers and validators for RoboDR's secure delivery formats
//! (`docs/SECURE-DELIVERY.md` §3, Sprint 13a):
//!
//! * [`rpk`]: one deliverable, `robodr-pkg/1` (manifest, chunking, kinds,
//!   health checks, site policy);
//! * [`bundle`]: one transfer across the air gap, `robodr-bundle/1`
//!   (signed file list, per-programme chain);
//! * [`deployment`]: an assignment of RPKs to units, `robodr-deployment/1`
//!   (depot + operator quorum by ring, freshness, replay);
//! * [`trust`]: the site's delivery trust file, `robodr-delivery-trust/1`
//!   (roles, quorums, revocations, floors, root rotation);
//! * [`entry`]: the entry station's signed scan report of one bundle,
//!   `robodr-entry-report/1` (Sprint 14a, §6.1);
//! * [`sig`]: detached signature sets `robodr-sigset/1` and quorum checks;
//! * [`parity`]: Reed-Solomon parity over bundle files with
//!   `robodr-diode`'s code;
//! * [`common`]: refusal codes, the canonical-JSON reader, validators.
//!
//! **No I/O.** Every function takes the bytes it judges (or callbacks that
//! supply them) and returns a value or a [`Refusal`]; reading trees,
//! writing files and the CLI are in `robodr-release`. Every parser has a
//! hard size cap checked before parsing, refuses unknown members,
//! duplicate keys and non-canonical encodings, and is fuzzed (`fuzz/`
//! targets `pkg_*`, std-only smoke runs in `tests/fuzz_smoke.rs`).
//!
//! Signing keys are `robodr-blackbox` Ed25519 keys (`robodr-blackbox-key/v2`)
//! through its `Signer` trait; verification is strict Ed25519 over
//! domain-separated messages.

// S10: no unsafe code at all in this crate.
#![forbid(unsafe_code)]
// Review L3 (S10, R9): the release tool, and later the depot and the unit
// agent, link this library and release builds use `panic = "abort"`, so a
// panic here kills the process. Non-test code has no unwrap / expect /
// panic!-family call; slice indexing and arithmetic are left to review and
// fuzzing.
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

pub mod bundle;
pub mod common;
pub mod deployment;
pub mod entry;
pub mod parity;
pub mod rpk;
pub mod sig;
pub mod trust;

pub use common::{Code, Refusal};

/// Largest integer any format accepts: `2^53 - 1`, so every JSON parser
/// (including IEEE-754-double ones in other languages) reads sequence
/// numbers, serials and times exactly.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
