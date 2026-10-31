//! `robodr-agentd --config FILE [--check-config]`: run the RoboDR daemon.
//! `robodr-agentd selftest --config FILE [--timeout SECS]`: field
//! acceptance self-test against the running daemon
//! (`robodr_agentd::selftest`; exit 0 acknowledged by the exporter, 1 not
//! proven, 2 usage or configuration error).
//!
//! Exit codes: 0 clean shutdown (signal, or every input ended with
//! `exit_when_inputs_end`); 1 runtime failure (black box could not be
//! sealed, ...); 2 usage or configuration error (nothing was started).
//! Keys are never taken from the command line: see `blackbox.key_file`.

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

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
robodr-agentd: RoboDR live daemon (capture / pcap / JSONL events -> pipeline -> decision chain
-> signed black box -> OCSF findings spool). Read-only; plans are recorded, never executed.

USAGE:
    robodr-agentd --config <agentd.json> [--check-config]
    robodr-agentd selftest --config <agentd.json> [--timeout <secs>]

    --config <file>   the daemon configuration (JSON, strict); see the crate README
    --check-config    validate the configuration and every file it names, then exit
    selftest          field acceptance: ask the running daemon (same configuration) to
                      spool a marked Low robot.agent.selftest finding, then wait until
                      the exporter acknowledges it (acked/) or rejects it (rejected/);
                      prints the nonce the SOC finds in the finding's detail
    --timeout <secs>  selftest deadline, 1..=3600 (default 120)
    -h, --help        this help
    -V, --version     version

Stops cleanly on SIGTERM / SIGINT (black box sealed, checkpoint copied to the spool).
EXIT: 0 clean stop, 1 runtime failure, 2 usage or configuration error.
selftest EXIT: 0 acknowledged by the exporter, 1 not proven, 2 usage or configuration error.
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
    let selftest = argv.first().is_some_and(|a| a == "selftest");
    let mut timeout: Option<u64> = None;
    let mut args = argv.into_iter().skip(usize::from(selftest));
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!(
                    "{}",
                    robodr_buildinfo::version_line("robodr-agentd", env!("CARGO_PKG_VERSION"))
                );
                return ExitCode::SUCCESS;
            }
            "--check-config" if !selftest => check = true,
            "--timeout" if selftest => match args.next().map(|v| v.parse::<u64>()) {
                Some(Ok(v)) if timeout.is_none() && (1..=3600).contains(&v) => timeout = Some(v),
                _ => {
                    eprintln!("error: --timeout needs one value of 1..=3600 seconds\n\n{USAGE}");
                    return ExitCode::from(2);
                }
            },
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
    if selftest {
        // Only the spool is needed: the configuration is parsed strictly,
        // but no key or profile is read (they may be readable only by the
        // service, e.g. systemd credentials).
        let spool = match robodr_agentd::selftest::spool_of_config(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "robodr-agentd: configuration error: {}",
                    robodr_ros2_pipeline::sanitize(&e)
                );
                return ExitCode::from(2);
            }
        };
        let opts = robodr_agentd::selftest::ClientOptions {
            timeout: std::time::Duration::from_secs(timeout.unwrap_or(120)),
            ..Default::default()
        };
        let mut out = std::io::stdout();
        return match robodr_agentd::selftest::run_client(&spool, opts, &mut out) {
            robodr_agentd::selftest::Outcome::Acked { .. } => ExitCode::SUCCESS,
            robodr_agentd::selftest::Outcome::Failed(_) => ExitCode::from(1),
        };
    }
    // --check-config before the first start: the keys are checked where the
    // unit loads them from (review 2, M18).
    let loaded = if check {
        let dirs: Vec<&std::path::Path> = robodr_agentd::unit_credentials::UNIT_DIRS
            .iter()
            .map(std::path::Path::new)
            .collect();
        let in_unit = std::env::var_os("CREDENTIALS_DIRECTORY").is_some();
        robodr_agentd::load_for_check(&path, &dirs, in_unit)
    } else {
        robodr_agentd::load(&path).map(|r| (r, Vec::new()))
    };
    let (resolved, check_notes) = match loaded {
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
        for n in &check_notes {
            eprintln!("robodr-agentd: {}", robodr_ros2_pipeline::sanitize(n));
        }
        for w in &resolved.warnings {
            eprintln!(
                "robodr-agentd: warning: {}",
                robodr_ros2_pipeline::sanitize(w)
            );
        }
        for k in &resolved.key_protection.keys {
            eprintln!(
                "robodr-agentd: key {}: {}{}",
                k.role,
                k.protection,
                if k.fallback {
                    " (not TPM-sealed: file fallback, flagged in status.json)"
                } else {
                    ""
                }
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
