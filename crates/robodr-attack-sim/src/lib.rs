//! # robodr-attack-sim
//!
//! Packaged attack simulator for RoboDR proofs of concept and demos
//! (gap T30). It carries the network scenarios of the lab red team
//! (`tools/e2e/redteam_net.py`, `rtlib.py`) as a std-only library and CLI:
//!
//! | Scenario | What it does | Findings it must produce |
//! |---|---|---|
//! | `rogue-participant` | an SPDP announcement cloned from the carrier with a new GUID prefix, from the attacker address | [`Scenario::expected`] |
//! | `guid-spray` | thousands of SPDP announcements, each with a random GUID prefix | |
//! | `malformed-rtps` | truncated headers, bad submessage lengths, random bodies, mutated bytes | |
//! | `cmd-vel-envelope` | the legitimate operator's `geometry_msgs/Twist` samples rewritten to an out-of-envelope speed (a spoofed, authorised writer) | |
//! | `lowcmd-torque` | Unitree legacy-UDP `LowCmd` frames with a joint torque far over any envelope, from an unlisted sender | |
//!
//! Three ways to use a scenario:
//!
//! * [`generate`]: offline. The scenario's frames are merged into a
//!   *carrier* capture of the robot's normal traffic and written as a pcap
//!   for `robodr-agentd`'s `pcap_replay` input. Nothing touches a network.
//! * [`guard::LiveTarget`] + the CLI's `send`: live, UDP payloads only, to
//!   one target address that must be in an explicit allow-list, with
//!   `--i-understand`; public addresses are refused outright.
//! * [`score`]: reads the findings the daemon produced (spool directory or
//!   NDJSON) and reports, per scenario, which expected rule ids were seen,
//!   so a POC report is scored automatically.
//!
//! The expected rule ids are asserted against the real daemon by
//! `tests/agentd_e2e.rs`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod guard;
pub mod net;
pub mod rng;
pub mod scenario;
pub mod score;

pub use scenario::{
    attack_frames, generate, read_capture, write_capture, Frame, Params, Scenario, SimError,
};
