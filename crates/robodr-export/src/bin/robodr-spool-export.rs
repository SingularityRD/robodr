//! `robodr-spool-export`: agentd findings spool -> diode packer outbox.
//! See `robodr_export::spool_export`.

use robodr_diode::cli::{argv, load_signer, parse_args_with_switches, Args};
use robodr_diode::{PackConfig, Packer};
use robodr_export::{now_ms, ExportConfig, Exporter};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: robodr-spool-export --spool DIR --outbox DIR --state FILE \
--pack-state FILE --unit ID --key-file FILE [--key-id ID] [--allow-hmac] \
[--max-batch-bytes N] [--max-findings N] [--rejected-dir DIR] [--interval-ms N] [--once]";

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
    let mut cfg = ExportConfig::new(a.req("spool")?, a.req("state")?);
    cfg.max_batch_bytes = pack.max_batch_bytes;
    cfg.max_findings_per_batch = pack.max_findings_per_batch;
    if let Some(d) = a.one("rejected-dir")? {
        cfg.rejected_dir = d.into();
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
    let mut x = Exporter::open(o.cfg.clone(), packer).map_err(|e| e.to_string())?;
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
    let parsed = argv().and_then(|v| {
        parse_args_with_switches(
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
            ],
            &["allow-hmac", "once"],
        )
    });
    let o = match parsed.and_then(|a| opts(&a)) {
        Ok(o) => o,
        Err(e) => {
            if e != "help" {
                eprintln!("robodr-spool-export: {e}");
            }
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
