//! # robodr-fleet
//!
//! The robot side of the fleet lifecycle (GA-ROADMAP Sprint 9; contract
//! `docs/contracts/robodr.fleet-api.md`), behind one binary,
//! `robodr-enroll`:
//!
//! * [`enroll`]: one-time enrollment with a single-use, SOC-signed token;
//!   the unit's keys (uplink, finding, black-box) are generated on the unit
//!   and never leave it; the request is signed by each of the three new
//!   keys (proof of possession) and MAC'd with the token secret; online
//!   over HTTPS or as files on vetted media (air-gapped).
//! * [`rotate`]: key rotation of the `uplink` and `finding` roles with
//!   overlap (the old key stays valid until the SOC confirms), an atomic
//!   swap, a crash-safe journal, a signed key handover in the fleet
//!   journal, and cancellation at the SOC (signed by the old key) of a
//!   rotation that was sent but will not be completed.
//! * [`revocation`]: the SOC-distributed, root-signed revocation list
//!   (`robodr-profile-revocations/v2`), verified with robodr-commission's
//!   code and anti-rollback protected.
//! * [`profile`]: SOC-published signed profiles are fetched, verified with
//!   agentd's own trust inputs and **staged**; they are installed only on an
//!   explicit operator approval artefact signed by a SOC **approval key**
//!   (distinct from the online fleet key). Nothing is ever
//!   enforced automatically.
//! * [`ring`]: update-ring information (0/1/2), information only.
//!
//! Supporting modules: [`wire`] (formats, pure), [`b64`], [`client`] (the
//! HTTPS client is robodr-uplink's), [`keys`], [`state`], [`journal`] (the
//! fleet journal, a robodr-blackbox recorder), [`config`], [`fsx`],
//! [`install`].
//!
//! Scope: protective only. Nothing here talks to the motion stack, and
//! nothing the SOC sends is executed: tokens, answers, approvals and ring
//! information are verified data; profiles take effect only through
//! agentd's own verification at its next start.

// S10: `unsafe` is denied crate-wide; the one item that needs it (`flock(2)`
// in `fsx`, FFI to a libc symbol std already links) carries a local
// `#[allow(unsafe_code)]` and a `// SAFETY:` comment on its block.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// S10 (R9): release builds use `panic = "abort"`, so a panic aborts
// `robodr-enroll` mid-step; every step is journaled and resumes at the next
// run (docs/OPERATIONS.md 8.6). Non-test code has no unwrap / expect /
// panic!-family call; slice indexing and arithmetic are left to review.
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

pub mod b64;
pub mod client;
pub mod config;
pub mod enroll;
pub mod fsx;
pub mod install;
pub mod journal;
pub mod keys;
pub mod profile;
pub mod revocation;
pub mod ring;
pub mod rotate;
pub mod state;
pub mod wire;
