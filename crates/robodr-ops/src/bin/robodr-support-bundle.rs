//! `robodr-support-bundle`: a redacted diagnostics bundle for RoboDR support
//! (sales-readiness T69). See `man robodr-support-bundle` and
//! `robodr_ops::bundle`.

#![forbid(unsafe_code)]

use robodr_ops::args::{argv, Args};
use robodr_ops::bundle::{self, Options};
use robodr_ops::exec::Host;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: robodr-support-bundle [--out-dir DIR] [--since -48h] [--journal-lines N]
                             [--no-journal] [--no-tar] [--root DIR]
Writes robodr-support-<host>-<UTC>.tar.gz (mode 0600) into --out-dir (default /var/tmp):
versions, unit state and journal, status files, the nftables ruleset and the
configuration in /etc/robodr, redacted, with manifest.json and SHA256SUMS. Keys,
credentials, evidence and findings are never collected; a bundle in which secret key
material is found is deleted (exit 1). Run as root for the complete picture.
Exit: 0 written, 1 failed, 2 usage.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("robodr-support-bundle: {msg}");
            if code == 2 {
                eprintln!("{USAGE}");
            }
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<(), (u8, String)> {
    let raw = argv().map_err(|e| (2, e))?;
    if raw.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if raw.iter().any(|a| a == "-V" || a == "--version") {
        println!("robodr-support-bundle {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let a = Args::parse(
        &raw,
        &["out-dir", "since", "journal-lines", "root"],
        &["no-journal", "no-tar"],
    )
    .map_err(|e| (2, e))?;
    if let Some(p) = a.positional.first() {
        return Err((2, format!("unexpected argument {p:?}")));
    }
    let one = |n: &str| a.one(n).map_err(|e| (2, e));
    let root = PathBuf::from(one("root")?.unwrap_or("/"));
    let out_dir = PathBuf::from(one("out-dir")?.unwrap_or("/var/tmp"));
    if !root.is_absolute() || !out_dir.is_absolute() {
        return Err((2, "--root and --out-dir must be absolute paths".into()));
    }
    let since = one("since")?.unwrap_or("-48h").to_string();
    // journalctl --since: a relative time or a date; no option injection.
    if since.is_empty()
        || since.len() > 32
        || !since
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | ':' | ' ' | '.'))
        || since.starts_with("--")
    {
        return Err((
            2,
            format!("--since {since:?}: e.g. -48h or \"2026-10-30 12:00\""),
        ));
    }
    let opts = Options {
        root,
        out_dir,
        since,
        journal_lines: a.u64_or("journal-lines", 20_000).map_err(|e| (2, e))?,
        journal: !a.flag("no-journal"),
        tar: !a.flag("no-tar"),
        now: std::time::SystemTime::now(),
    };
    let host = Host::default();
    let w = bundle::collect(&opts, &host).map_err(|e| (1, e))?;
    println!("{}", w.path.display());
    eprintln!(
        "robodr-support-bundle: {} files, {} items not collected (see manifest.json){}",
        w.files,
        w.skipped,
        w.sha256
            .map(|s| format!(", sha256 {s}"))
            .unwrap_or_default()
    );
    Ok(())
}
