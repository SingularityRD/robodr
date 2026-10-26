//! `robodr-spool-export`: agentd findings spool -> diode packer outbox.
//! See `robodr_export::spool_export`.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_diode::cli::{argv, is_version_request, load_signer, parse_args_with_switches, Args};
use robodr_diode::{PackConfig, Packer};
use robodr_export::{now_ms, ExportConfig, Exporter};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: robodr-spool-export --spool DIR --outbox DIR --state FILE \
--pack-state FILE --unit ID --key-file FILE [--key-id ID] [--allow-hmac] \
[--max-batch-bytes N] [--max-findings N] [--rejected-dir DIR] [--interval-ms N] [--once] \
[--upgrade-data-source LABEL] [--upgrade-topic TOPIC]\n\
Unsigned contract 1.x records (spooled before an upgrade) are upgraded to contract 2.0 with \
--upgrade-data-source (default robodr) and --upgrade-topic (default robodr.findings); signed \
ones are moved to the rejected directory (\"legacy 1.x signed record: re-sign required\").";

struct Opts {
    cfg: ExportConfig,
    outbox: PathBuf,
    pack_state: PathBuf,
    pack: PackConfig,
    key_file: PathBuf,
    key_id: Option<String>,
    allow_hmac: bool,
    interval: Duration,
    once: bool,
}

fn opts(a: &Args) -> Result<Opts, String> {
    let mut pack = PackConfig::new(a.req("unit")?);
    if let Some(n) = a.num("max-batch-bytes")? {
        pack.max_batch_bytes = n;
    }
    if let Some(n) = a.num("max-findings")? {
        pack.max_findings_per_batch = n;
    }
    let mut cfg = ExportConfig::for_packer(a.req("spool")?, a.req("state")?, &pack);
    if let Some(d) = a.one("rejected-dir")? {
        cfg.rejected_dir = d.into();
    }
    if let Some(l) = a.one("upgrade-data-source")? {
        cfg.upgrade_data_source = l.into();
    }
    if let Some(t) = a.one("upgrade-topic")? {
        cfg.upgrade_topic = t.into();
    }
    let interval: u64 = a.num("interval-ms")?.unwrap_or(5_000);
    if interval == 0 {
        return Err("--interval-ms must be > 0".into());
    }
    Ok(Opts {
        cfg,
        outbox: a.req("outbox")?.into(),
        pack_state: a.req("pack-state")?.into(),
        pack,
        key_file: a.req("key-file")?.into(),
        key_id: a.one("key-id")?.map(str::to_string),
        allow_hmac: a.flag("allow-hmac"),
        interval: Duration::from_millis(interval),
        once: a.flag("once"),
    })
}

fn run_one(o: &Opts) -> Result<(), String> {
    let (signer, warning) = load_signer(&o.key_file, o.key_id.as_deref(), o.allow_hmac)?;
    if let Some(w) = warning {
        eprintln!("{w}");
    }
    let packer = Packer::open(&o.outbox, &o.pack_state, o.pack.clone(), signer)
        .map_err(|e| format!("packer: {e}"))?;
    let mut x =
        Exporter::open_checked(o.cfg.clone(), &o.pack, packer).map_err(|e| e.to_string())?;
    loop {
        let r = x.run_once(now_ms()).map_err(|e| e.to_string())?;
        if r.exported > 0 || !r.rejected.is_empty() || r.recovered.is_some() {
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }
        if o.once {
            return Ok(());
        }
        std::thread::sleep(o.interval);
    }
}

fn main() -> ExitCode {
    let v = match argv() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("robodr-spool-export: {e}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if is_version_request(&v) {
        println!("robodr-spool-export {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let parsed = parse_args_with_switches(
        v,
        &[
            "spool",
            "outbox",
            "state",
            "pack-state",
            "unit",
            "key-file",
            "key-id",
            "max-batch-bytes",
            "max-findings",
            "rejected-dir",
            "interval-ms",
            "upgrade-data-source",
            "upgrade-topic",
        ],
        &["allow-hmac", "once"],
    );
    let o = match parsed.and_then(|a| opts(&a)) {
        Ok(o) => o,
        Err(e) if e == "help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("robodr-spool-export: {e}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    loop {
        match run_one(&o) {
            Ok(()) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("robodr-spool-export: {e}");
                if o.once {
                    return ExitCode::from(1);
                }
                // Re-open from scratch: the packer and the exporter recover
                // a half-finished batch on open.
                std::thread::sleep(o.interval);
            }
        }
    }
}
