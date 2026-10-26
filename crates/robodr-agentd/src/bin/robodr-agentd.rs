//! `robodr-agentd --config FILE [--check-config]`: run the RoboDR daemon.
//!
//! Exit codes: 0 clean shutdown (signal, or every input ended with
//! `exit_when_inputs_end`); 1 runtime failure (black box could not be
//! sealed, ...); 2 usage or configuration error (nothing was started).
//! Keys are never taken from the command line: see `blackbox.key_file`.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
robodr-agentd: RoboDR live daemon (capture / pcap / JSONL events -> pipeline -> decision chain
-> signed black box -> OCSF findings spool). Read-only; plans are recorded, never executed.

USAGE:
    robodr-agentd --config <agentd.json> [--check-config]

    --config <file>   the daemon configuration (JSON, strict); see the crate README
    --check-config    validate the configuration and every file it names, then exit
    -h, --help        this help
    -V, --version     version

Stops cleanly on SIGTERM / SIGINT (black box sealed, checkpoint copied to the spool).
EXIT: 0 clean stop, 1 runtime failure, 2 usage or configuration error.
";

fn main() -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut check = false;
    // args_os: std::env::args() panics on an argument that is not valid
    // Unicode; that is a usage error here.
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("error: an argument is not valid UTF-8\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut args = argv.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("robodr-agentd {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--check-config" => check = true,
            "--config" => match args.next() {
                Some(v) if config.is_none() => config = Some(PathBuf::from(v)),
                Some(_) => {
                    eprintln!("error: --config given twice\n\n{USAGE}");
                    return ExitCode::from(2);
                }
                None => {
                    eprintln!("error: --config needs a value\n\n{USAGE}");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!(
                    "error: unknown argument {:?}\n\n{USAGE}",
                    robodr_ros2_pipeline::sanitize(other)
                );
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = config else {
        eprintln!("error: --config is required\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let resolved = match robodr_agentd::load(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "robodr-agentd: configuration error: {}",
                robodr_ros2_pipeline::sanitize(&e)
            );
            return ExitCode::from(2);
        }
    };
    if check {
        for w in &resolved.warnings {
            eprintln!(
                "robodr-agentd: warning: {}",
                robodr_ros2_pipeline::sanitize(w)
            );
        }
        eprintln!("robodr-agentd: configuration OK");
        return ExitCode::SUCCESS;
    }
    if let Err(e) = robodr_agentd::signal::install() {
        eprintln!("robodr-agentd: cannot install signal handlers: {e}");
        return ExitCode::from(1);
    }
    let mut log = std::io::stderr();
    match robodr_agentd::run(&resolved, &robodr_agentd::signal::requested, &mut log) {
        Ok(s) => {
            eprintln!(
                "robodr-agentd: final state {:?} ({})",
                s.last_state.state,
                s.last_state.reasons.join("; ")
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "robodr-agentd: {}",
                robodr_ros2_pipeline::sanitize(&e.to_string())
            );
            match e {
                robodr_agentd::DaemonError::Config(_) => ExitCode::from(2),
                _ => ExitCode::from(1),
            }
        }
    }
}
