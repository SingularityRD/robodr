//! `robodr-ros2-watch`: see `robodr_ros2_pipeline::watch` for the contract.

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
            println!("robodr-ros2-watch {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
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
