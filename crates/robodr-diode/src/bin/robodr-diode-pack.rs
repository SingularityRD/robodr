//! `robodr-diode-pack`: low-side packer (see the crate README).
//!
//! Exit codes: 0 ok, 1 error, 2 usage.

use robodr_diode::cli::{self, MAX_INPUT_FILE};
use robodr_diode::pack::{PackConfig, Packer};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
usage: robodr-diode-pack --outbox DIR --state FILE --unit UNIT_ID \\
         --key-id KEY_ID --key-file HEX_KEY_FILE \\
         [--findings FINDINGS.jsonl]... [--bundle BUNDLE.rbbx]... \\
         [--max-batch-bytes N] [--max-findings N] [--now-ms MS]

Validates every finding (robodr_ocsf::parse_and_validate) and bundle, then
writes signed, sequence-numbered batches into OUTBOX (atomic rename; the
transfer agent must ignore dot-entries). Prints the published batches as JSON.
Any invalid input aborts before anything is written.";

const FLAGS: &[&str] = &[
    "outbox",
    "state",
    "unit",
    "key-id",
    "key-file",
    "findings",
    "bundle",
    "max-batch-bytes",
    "max-findings",
    "now-ms",
];

fn main() -> ExitCode {
    let args = match cli::argv().and_then(|v| cli::parse_args(v, FLAGS)) {
        Ok(a) => a,
        Err(e) if e == "help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &cli::Args) -> Result<(), String> {
    let key_path = Path::new(args.req("key-file")?);
    if let Some(w) = cli::key_file_mode_warning(key_path) {
        eprintln!("{w}");
    }
    let key = cli::load_hmac_key(args.req("key-id")?, key_path)?;
    let mut cfg = PackConfig::new(args.req("unit")?);
    if let Some(n) = args.num("max-batch-bytes")? {
        cfg.max_batch_bytes = n;
    }
    if let Some(n) = args.num("max-findings")? {
        cfg.max_findings_per_batch = n;
    }
    let now = args.num("now-ms")?.unwrap_or_else(cli::now_ms);

    let mut texts = Vec::new();
    for f in args.all("findings") {
        let b = cli::read_file(Path::new(f), MAX_INPUT_FILE)?;
        let t = String::from_utf8(b).map_err(|_| format!("{f}: not UTF-8"))?;
        texts.push((f, t));
    }
    let mut lines = Vec::new();
    let mut origin = Vec::new();
    for (f, t) in &texts {
        for (i, l) in t.lines().enumerate() {
            if l.trim().is_empty() {
                continue;
            }
            lines.push(l);
            origin.push(format!("{f}:{}", i + 1));
        }
    }
    let mut bundles = Vec::new();
    for b in args.all("bundle") {
        bundles.push(cli::read_file(Path::new(b), MAX_INPUT_FILE)?);
    }

    let mut packer = Packer::open(args.req("outbox")?, args.req("state")?, cfg, Box::new(key))
        .map_err(|e| e.to_string())?;
    let published = packer
        .pack_lines(&lines, &bundles, now)
        .map_err(|e| match e {
            robodr_diode::PackError::InvalidFinding { index, .. } => {
                format!("{} ({})", e, origin.get(index).map_or("?", String::as_str))
            }
            e => e.to_string(),
        })?;
    println!(
        "{}",
        serde_json::to_string_pretty(&published).map_err(|e| e.to_string())?
    );
    Ok(())
}
