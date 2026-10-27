//! `robodr-safety-replay`: replay recorded safety reports into agentd's
//! `safety_feed` socket (tests and demos; see
//! `robodr_deliverd::cli::REPLAY_USAGE`). Exit codes: 0 ok, 1 error,
//! 2 usage.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(robodr_deliverd::cli::main_replay() as u8)
}
