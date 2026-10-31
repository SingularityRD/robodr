//! `robodr-deliverd`: the on-unit delivery agent (see
//! `robodr_deliverd::cli::USAGE`). Exit codes: 0 ok, 1 refused or error,
//! 2 usage.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(robodr_deliverd::cli::main_deliverd() as u8)
}
