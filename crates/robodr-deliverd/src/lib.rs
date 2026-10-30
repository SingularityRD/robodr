//! # robodr-deliverd
//!
//! The on-unit delivery agent of RoboDR's secure delivery
//! (`docs/SECURE-DELIVERY.md` §2.1, §4.2, §6, Sprint 13b). It takes a
//! **per-unit media pack** (a site trust file, one deployment for this
//! unit and the release bundles that carry its items), imports it only
//! through the verified-copy path of `robodr-release` (13a, §3.5 item 30),
//! and then, item by item:
//!
//! 1. checks the deployment against the unit (its own site, ring, unit id,
//!    architecture, platform, floors, dependencies; [`media`]);
//! 2. fills its content-addressed store from the verified copy, hashing
//!    every chunk as it is written ([`store`]);
//! 3. prepares the new version next to the running one ([`install`]);
//! 4. waits for the safety-state gate: agentd's **live** safety feed must
//!    say `idle` or `safe_state_active`, inside the deployment's
//!    maintenance window and after a local operator confirmation when the
//!    RPK asks for one; the state is read again immediately before the
//!    switch ([`safety`], [`engine`]);
//! 5. raises the anti-rollback floor and switches (symlink swap, or
//!    `dpkg -i`) under a write-ahead intent in the state file ([`state`]);
//! 6. runs the RPK's health checks (probes executed without a shell, as an
//!    unprivileged UID, bounded in time and output; [`health`],
//!    [`runner`], [`users`]);
//! 7. rolls back to the previous version at or above the floor when the
//!    health gate fails, or raises a Critical finding when there is none.
//!
//! Every step is a note in a black-box chain of its own ([`journal`]) and
//! the §9 `robot.deliver.*` findings go into agentd's findings spool
//! ([`findings`]). [`replay`] is the small helper that replays recorded
//! safety reports into agentd's `safety_feed` socket (tests, demos).
//!
//! Sealed RPKs (13c, [`sealing`]): a sealed `files`, `model` or `config`
//! RPK is staged by unwrapping its content key with the unit's UWK
//! (`robodr-seal`: TPM under the signed PCR policy, or the fallback key on
//! the runtime volume) and opening its chunks straight into the sealed
//! runtime volume; every `model` is installed there too. `robodr-deliverd
//! erase` crypto-erases the unit's keys.
//!
//! Not here: the depot and LAN delivery (14a), the lease and executed
//! erase triggers (14b), OS A/B updates (14c), and the kinds `oci-image`,
//! `robodr-profile` and `os-image` (refused as `unsupported`).

// S10: `unsafe` is denied crate-wide; the items that need it (FFI to
// libc, which std already links: `kill(2)`, `prctl`, `setrlimit`, `setsid` and `getsid` in
// `runner`, the `*at` calls of `fdio`) carry a local
// `#[allow(unsafe_code)]` and a `// SAFETY:` comment.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// Review L3 (S10, R9): release builds use `panic = "abort"`, so a panic
// kills the daemon. Non-test code has no unwrap / expect / panic!-family
// call and no unchecked indexing; arithmetic is left to review and fuzzing.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod cli;
pub mod clock;
pub mod config;
pub mod debfs;
pub mod engine;
pub mod erasex;
pub mod fault;
pub mod fdio;
pub mod findings;
pub mod fsx;
pub mod health;
pub mod highwater;
pub mod install;
pub mod journal;
pub mod lan;
pub mod media;
pub mod rekey;
pub mod replay;
pub mod rules;
pub mod runner;
pub mod safety;
pub mod sealing;
pub mod state;
pub mod store;
pub mod users;

pub use config::Config;
pub use engine::Engine;
