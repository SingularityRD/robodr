//! `robodr-release`: build, sign, verify and repair delivery artifacts
//! (see `robodr_release::cli::USAGE`).
//!
//! Exit codes: 0 ok, 1 refused or error, 2 usage.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(robodr_release::cli::main_with_env() as u8)
}
