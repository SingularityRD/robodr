//! `robodr-ros2-watch`: see `robodr_ros2_pipeline::watch` for the contract.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// daemon (systemd restarts it; docs/OPERATIONS.md, "Crashes and restarts").
// Non-test code has no unwrap / expect / panic!-family call and no
// unchecked indexing (a proven bound carries a local allow and a `// bound:`
// note); arithmetic is left to review and fuzzing (fuzz/README.md).
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

use std::process::ExitCode;

use robodr_ros2_pipeline::watch::{parse_args, run, Command, USAGE};

fn main() -> ExitCode {
    let cmd = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("robodr-ros2-watch: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let args = match cmd {
        Command::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!(
                "{}",
                robodr_buildinfo::version_line("robodr-ros2-watch", env!("CARGO_PKG_VERSION"))
            );
            return ExitCode::SUCCESS;
        }
        Command::CheckConfig { path, strict } => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let ok = robodr_ros2_pipeline::watch::run_check(
                &path,
                strict,
                &mut stdout.lock(),
                &mut stderr.lock(),
            );
            return if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
        Command::Run(a) => a,
    };
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    match run(&args, &mut stdout.lock(), &mut stderr.lock()) {
        Ok(summary) if summary.source_error.is_none() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(e) => {
            eprintln!("robodr-ros2-watch: error: {e}");
            ExitCode::from(1)
        }
    }
}
