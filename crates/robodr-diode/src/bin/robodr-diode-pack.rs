//! `robodr-diode-pack`: low-side packer (see the crate README).
//!
//! `robodr-diode-pack resend ...` re-emits an archived batch.
//!
//! Exit codes: 0 ok, 1 error (including "another instance holds the
//! lock"), 2 usage.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_diode::cli::{self, MAX_INPUT_FILE};
use robodr_diode::pack::{PackConfig, Packer};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
usage: robodr-diode-pack --outbox DIR --state FILE --unit UNIT_ID \\
         --key-file SECRET_KEY_FILE [--key-id KEY_ID] [--allow-hmac] \\
         [--findings FINDINGS.jsonl]... [--bundle BUNDLE.rbbx]... \\
         [--max-batch-bytes N] [--max-findings N] [--now-ms MS] \
         [--parity M] [--shard-size BYTES] [--archive-keep N]
       robodr-diode-pack resend --outbox DIR --state FILE --unit UNIT_ID --seq N
       robodr-diode-pack --version

--key-file is a robodr-blackbox secret key file (`robodr-blackbox keygen`,
ed25519; mode 0600, owned by this user or root, else refused). --key-id, if
given, must equal the file's key id. Legacy hmac-sha256 key files are refused
unless --allow-hmac is given (symmetric: the SOC could forge batches).

Validates every finding (robodr_ocsf::parse_and_validate) and bundle, then
writes signed, sequence-numbered batches into OUTBOX (atomic rename; the
transfer agent must ignore dot-entries). Prints the published batches as JSON.
Any invalid input aborts before anything is written.

--parity M (default 0 = off, max 32) adds M Reed-Solomon parity files to
every batch, so the importer can rebuild any M missing or corrupt files of
it; each parity file is the largest data file rounded up to --shard-size
(default 65536) and counts against --max-batch-bytes.
--archive-keep N (default 64, 0 = off) keeps the newest N batches in
STATE.archive/ for `resend`, which copies batch SEQ back into OUTBOX byte for
byte (no key needed; a no-op if an identical copy is already there).
Only one packer may use a state file at a time (flock on STATE.lock).";

const RESEND_FLAGS: &[&str] = &["outbox", "state", "unit", "seq"];

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
    "parity",
    "shard-size",
    "archive-keep",
];

const SWITCHES: &[&str] = &["allow-hmac"];

fn main() -> ExitCode {
    let argv = match cli::argv() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if cli::is_version_request(&argv) {
        println!(
            "{}",
            robodr_buildinfo::version_line("robodr-diode-pack", env!("CARGO_PKG_VERSION"))
        );
        return ExitCode::SUCCESS;
    }
    if argv.first().map(String::as_str) == Some("resend") {
        let args = match cli::parse_args(argv.into_iter().skip(1), RESEND_FLAGS) {
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
        return match resend(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }
    let args = match cli::parse_args_with_switches(argv, FLAGS, SWITCHES) {
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
    let (key, warning) = cli::load_signer(
        Path::new(args.req("key-file")?),
        args.one("key-id")?,
        args.flag("allow-hmac"),
    )?;
    if let Some(w) = warning {
        eprintln!("{w}");
    }
    let mut cfg = PackConfig::new(args.req("unit")?);
    if let Some(n) = args.num("max-batch-bytes")? {
        cfg.max_batch_bytes = n;
    }
    if let Some(n) = args.num("max-findings")? {
        cfg.max_findings_per_batch = n;
    }
    if let Some(n) = args.num("parity")? {
        cfg.parity_shards = n;
    }
    if let Some(n) = args.num("shard-size")? {
        cfg.shard_size = n;
    }
    if let Some(n) = args.num("archive-keep")? {
        cfg.archive_keep = n;
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

    let mut packer = Packer::open(args.req("outbox")?, args.req("state")?, cfg, key)
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

fn resend(args: &cli::Args) -> Result<(), String> {
    let seq: u64 = args
        .num("seq")?
        .ok_or_else(|| "--seq is required".to_string())?;
    let mut packer =
        Packer::open_for_resend(args.req("outbox")?, args.req("state")?, args.req("unit")?)
            .map_err(|e| e.to_string())?;
    let r = packer.resend(seq).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?
    );
    Ok(())
}
