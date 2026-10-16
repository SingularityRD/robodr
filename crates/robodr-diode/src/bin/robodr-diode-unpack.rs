//! `robodr-diode-unpack`: SOC-side importer (see the crate README).
//!
//! Exit codes: 0 all clean, 3 something quarantined, held (gap) or a
//! per-entry I/O error (listed in the report; the run went on),
//! 1 error, 2 usage.

use robodr_diode::cli;
use robodr_diode::unpack::{ImportConfig, Importer};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
usage: robodr-diode-unpack --inbox DIR --out DIR --quarantine DIR \\
         --processed DIR --state FILE --keyring FILE \\
         [--bundle-key UNIT:PUBLIC_KEY_FILE]... [--allow-hmac] [--partitions N] \\
         [--accept-gap UNIT:SEQ]... [--max-accept-gap N] [--max-batch-bytes N] \\
         [--held-max-age-s N] [--in-transit-max-age-s N]

Keyring file: one `<unit_id> <public-key-file>` per line (# comments; the
older `<unit_id> <key_id> <key-file>` also works, the id must match the
file). Key files are robodr-blackbox ed25519 PUBLIC key files
(`robodr-blackbox export-pub`); an ed25519 secret key file is refused, so the
SOC holds no key that can sign batches. Legacy hmac-sha256 key files (secret,
mode 0600) are refused unless --allow-hmac is given. A keyring line
`robots: <unit_id> <robot_id>...` lets that unit report on those robots too;
otherwise every finding's robot id (and bundle device id) must be the unit.
--bundle-key UNIT:FILE adds a black-box key (same rules) used to verify
bundles inside batches of UNIT (a bundle signed with it in another unit's
batch is quarantined).
Accepted batches go to OUT/<batch>/records.jsonl (one Kafka record per line;
OUT/<batch>.<hash16>/ if OUT/<batch> holds another batch), rejected ones to
QUARANTINE/<unique>/entry with QUARANTINE/<unique>/reason.json. Prints a JSON
report; per-entry I/O errors are listed under \"errors\" and do not stop
the run.
--accept-gap accepts batch SEQ of UNIT although earlier batches are missing
(recorded in the state; the skipped batches will then be refused); at most
--max-accept-gap (default 100000) batches may be skipped.
Held batches older than --held-max-age-s (default 30 days) and dot-entries
older than --in-transit-max-age-s (default 24 h) are quarantined; 0 disables.";

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
    "max-accept-gap",
    "max-batch-bytes",
    "held-max-age-s",
    "in-transit-max-age-s",
];

const SWITCHES: &[&str] = &["allow-hmac"];

fn main() -> ExitCode {
    let args = match cli::argv().and_then(|v| cli::parse_args_with_switches(v, FLAGS, SWITCHES)) {
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
    let allow_hmac = args.flag("allow-hmac");
    let (keyring, warnings) = cli::load_keyring(Path::new(args.req("keyring")?), allow_hmac)?;
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
    if let Some(n) = args.num("max-accept-gap")? {
        cfg.max_accept_gap = n;
    }
    if let Some(s) = args.num::<u64>("held-max-age-s")? {
        cfg.held_max_age_ms = (s > 0).then(|| s.saturating_mul(1000));
    }
    if let Some(s) = args.num::<u64>("in-transit-max-age-s")? {
        cfg.in_transit_max_age_ms = (s > 0).then(|| s.saturating_mul(1000));
    }
    let mut importer = Importer::open(cfg, keyring).map_err(|e| e.to_string())?;
    for bk in args.all("bundle-key") {
        let (unit, file) = cli::parse_unit_file(bk)?;
        let (v, w) = cli::load_verifier(&file, allow_hmac)?;
        if let Some(w) = w {
            eprintln!("{w}");
        }
        importer
            .add_bundle_verifier(&unit, v)
            .map_err(|e| e.to_string())?;
    }
    let report = importer.run(cli::now_ms()).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(report.is_clean())
}
