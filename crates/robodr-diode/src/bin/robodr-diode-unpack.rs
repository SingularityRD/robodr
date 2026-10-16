//! `robodr-diode-unpack`: SOC-side importer (see the crate README).
//!
//! Exit codes: 0 all clean, 3 something quarantined or held (gap),
//! 1 error, 2 usage.

use robodr_diode::cli;
use robodr_diode::unpack::{ImportConfig, Importer};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
usage: robodr-diode-unpack --inbox DIR --out DIR --quarantine DIR \\
         --processed DIR --state FILE --keyring FILE \\
         [--bundle-key KEY_ID:HEX_KEY_FILE]... [--partitions N] \\
         [--accept-gap UNIT:SEQ]... [--max-batch-bytes N]

Keyring file: one `<unit_id> <key_id> <hex-key-file>` per line (# comments).
Accepted batches go to OUT/<batch>/records.jsonl (one Kafka record per line),
rejected ones to QUARANTINE/ with a .reason.json. Prints a JSON report.
--accept-gap accepts batch SEQ of UNIT although earlier batches are missing
(recorded in the state; the skipped batches will then be refused).";

const FLAGS: &[&str] = &[
    "inbox",
    "out",
    "quarantine",
    "processed",
    "state",
    "keyring",
    "bundle-key",
    "partitions",
    "accept-gap",
    "max-batch-bytes",
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
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(3),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &cli::Args) -> Result<bool, String> {
    let (keyring, warnings) = cli::load_keyring(Path::new(args.req("keyring")?))?;
    for w in warnings {
        eprintln!("{w}");
    }
    let mut cfg = ImportConfig::under(Path::new("."));
    cfg.inbox = PathBuf::from(args.req("inbox")?);
    cfg.out_dir = PathBuf::from(args.req("out")?);
    cfg.quarantine_dir = PathBuf::from(args.req("quarantine")?);
    cfg.processed_dir = PathBuf::from(args.req("processed")?);
    cfg.state_path = PathBuf::from(args.req("state")?);
    cfg.partitions = args.num("partitions")?;
    if let Some(n) = args.num("max-batch-bytes")? {
        cfg.max_batch_bytes = n;
    }
    for g in args.all("accept-gap") {
        cfg.accept_gaps.push(cli::parse_unit_seq(g)?);
    }
    let mut importer = Importer::open(cfg, keyring).map_err(|e| e.to_string())?;
    for bk in args.all("bundle-key") {
        let (id, file) = bk
            .split_once(':')
            .ok_or_else(|| format!("--bundle-key expects KEY_ID:FILE, got {bk:?}"))?;
        importer.add_bundle_verifier(Box::new(cli::load_hmac_key(id, Path::new(file))?));
    }
    let report = importer.run(cli::now_ms()).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(report.is_clean())
}
