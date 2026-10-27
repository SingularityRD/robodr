//! `robodr-anchor-receiver`: the off-unit home of black-box head marks
//! (`robodr_blackbox::remote_anchor`). Runs on a base station or fleet host,
//! never on the unit it anchors.
//!
//! ```text
//! robodr-anchor-receiver serve  --config FILE
//! robodr-anchor-receiver ingest --config FILE MARKFILE...
//! robodr-anchor-receiver status --config FILE
//! ```
//!
//! - `serve` listens on `listen` and answers `advance` / `current`
//!   requests (one JSON line each, `robodr-anchor/v1`). It prints
//!   `robodr-anchor-receiver: listening on ADDR` on stdout once bound;
//!   alerts and errors go to stderr (the journal) and to
//!   `<state_dir>/alerts.jsonl`.
//! - `ingest` applies mark files (written on the unit by
//!   `robodr-blackbox anchor-mark`, carried one way, e.g. through the
//!   diode) with the same rule: detect-only mode for units without a
//!   reverse channel. Needs the state directory's lock, so it cannot run
//!   while `serve` runs on the same directory. Exit 1 if any mark was
//!   refused (an alert was recorded), 0 otherwise.
//! - `status` prints, as JSON, what is held per unit (read-only, works
//!   while `serve` runs).
//!
//! Config (JSON, unknown fields refused, paths absolute):
//!
//! ```json
//! {"listen": "0.0.0.0:7461",
//!  "state_dir": "/var/lib/robodr-anchor-receiver",
//!  "key_file": "/etc/robodr-anchor-receiver/receiver.key",
//!  "units": [{"unit": "ugv-07",
//!             "public_key": "/etc/robodr-anchor-receiver/units/ugv-07-blackbox.key.pub"}],
//!  "max_connections": 64, "io_timeout_ms": 5000}
//! ```
//!
//! `key_file` is the receiver's own Ed25519 secret key file
//! (`robodr-blackbox keygen`; 0600, refused otherwise); the units are
//! configured with its `.pub`. `public_key` is each unit's black-box public
//! key file; a key bound to a device (`device_id`) must name that unit.
//!
//! Exit codes: 0 ok, 1 refused marks (`ingest`), 2 usage, config, key or
//! I/O error.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_blackbox::keys::KeyFile;
use robodr_blackbox::remote_anchor::{
    self, read_unit_state, AnchorReceiver, RemoteMark, ServeOptions, UnitKey, MAX_FRAME,
};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage:
  robodr-anchor-receiver serve  --config FILE
  robodr-anchor-receiver ingest --config FILE MARKFILE...
  robodr-anchor-receiver status --config FILE
  robodr-anchor-receiver --version
exit: 0 ok, 1 refused marks (ingest), 2 usage/config/key/IO error";

const MAX_CONFIG_BYTES: u64 = 1 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    listen: Option<String>,
    state_dir: PathBuf,
    key_file: PathBuf,
    units: Vec<UnitConfig>,
    #[serde(default)]
    max_connections: Option<usize>,
    #[serde(default)]
    io_timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitConfig {
    unit: String,
    public_key: PathBuf,
}

enum Fail {
    Usage(String),
    Refused,
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Usage(s)
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("robodr-anchor-receiver: an argument is not valid UTF-8\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let res = match argv.first().map(String::as_str) {
        Some("serve") => serve(&argv[1..]),
        Some("ingest") => ingest(&argv[1..]),
        Some("status") => status(&argv[1..]),
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("-V" | "--version") if argv.len() == 1 => {
            println!("robodr-anchor-receiver {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(Fail::Usage("missing or unknown subcommand".into())),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Refused) => ExitCode::from(1),
        Err(Fail::Usage(m)) => {
            eprintln!("robodr-anchor-receiver: {m}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// `--config FILE` and the positional arguments.
fn split_args(raw: &[String]) -> Result<(PathBuf, Vec<String>), String> {
    let mut config = None;
    let mut rest = Vec::new();
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => {
                let v = it.next().ok_or("--config needs a value")?;
                if config.replace(PathBuf::from(v)).is_some() {
                    return Err("--config given more than once".into());
                }
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => rest.push(s.to_string()),
        }
    }
    Ok((config.ok_or("--config FILE is required")?, rest))
}

fn read_bounded(p: &Path, max: u64) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut b = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if b.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", p.display()));
    }
    Ok(b)
}

fn abs(what: &str, p: &Path) -> Result<(), String> {
    if !p.is_absolute() {
        return Err(format!(
            "{what} must be an absolute path, got {}",
            p.display()
        ));
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<Config, String> {
    let b = read_bounded(path, MAX_CONFIG_BYTES)?;
    let c: Config = serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?;
    abs("state_dir", &c.state_dir)?;
    abs("key_file", &c.key_file)?;
    if c.units.is_empty() || c.units.len() > remote_anchor::MAX_UNITS {
        return Err(format!(
            "units: 1..={} entries required",
            remote_anchor::MAX_UNITS
        ));
    }
    for u in &c.units {
        abs(&format!("units[{}].public_key", u.unit), &u.public_key)?;
    }
    if let Some(l) = &c.listen {
        l.parse::<std::net::SocketAddr>()
            .map_err(|_| format!("listen {l:?}: expected IP:port (e.g. 0.0.0.0:7461)"))?;
    }
    if c.max_connections.is_some_and(|n| !(1..=4096).contains(&n)) {
        return Err("max_connections must be 1..=4096".into());
    }
    if c.io_timeout_ms
        .is_some_and(|t| !(100..=60_000).contains(&t))
    {
        return Err("io_timeout_ms must be 100..=60000".into());
    }
    Ok(c)
}

fn unit_keys(c: &Config) -> Result<Vec<UnitKey>, String> {
    c.units
        .iter()
        .map(|u| {
            if !remote_anchor::valid_unit_id(&u.unit) {
                return Err(format!(
                    "unit id {:?} must match [A-Za-z0-9._-]{{1,64}} (no leading dot)",
                    u.unit
                ));
            }
            let k = KeyFile::load_public(&u.public_key)
                .map_err(|e| format!("{}: {e}", u.public_key.display()))?;
            if let Some(d) = &k.device_id {
                if d != &u.unit {
                    return Err(format!(
                        "{}: key is bound to device {d:?}, not unit {:?}",
                        u.public_key.display(),
                        u.unit
                    ));
                }
            }
            let v = k
                .ed25519_verifying_key()
                .map_err(|e| format!("{}: {e}", u.public_key.display()))?;
            Ok(UnitKey {
                unit: u.unit.clone(),
                verifier: Box::new(v),
            })
        })
        .collect()
}

fn open_receiver(c: &Config) -> Result<AnchorReceiver, String> {
    let units = unit_keys(c)?;
    let key =
        KeyFile::load_secret(&c.key_file).map_err(|e| format!("{}: {e}", c.key_file.display()))?;
    let signer = key.ed25519_signing_key().map_err(|e| {
        format!(
            "{}: the receiver key must be ed25519: {e}",
            c.key_file.display()
        )
    })?;
    AnchorReceiver::open(&c.state_dir, units, Box::new(signer), None)
}

fn serve(raw: &[String]) -> Result<(), Fail> {
    let (cfg_path, rest) = split_args(raw)?;
    if !rest.is_empty() {
        return Err("serve takes no positional arguments".to_string().into());
    }
    let c = load_config(&cfg_path)?;
    let listen = c
        .listen
        .clone()
        .ok_or_else(|| "serve needs \"listen\" in the config".to_string())?;
    let r = Arc::new(open_receiver(&c)?);
    let l = TcpListener::bind(&listen).map_err(|e| format!("binding {listen}: {e}"))?;
    let bound = l
        .local_addr()
        .map_err(|e| format!("binding {listen}: {e}"))?;
    let opts = ServeOptions {
        max_connections: c
            .max_connections
            .unwrap_or(remote_anchor::DEFAULT_MAX_CONNECTIONS),
        io_timeout: c
            .io_timeout_ms
            .map_or(remote_anchor::DEFAULT_IO_TIMEOUT, Duration::from_millis),
    };
    {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "robodr-anchor-receiver: listening on {bound} ({} units)",
            c.units.len()
        );
        let _ = out.flush();
    }
    let stop = AtomicBool::new(false);
    r.serve(l, &opts, &stop)
        .map_err(|e| format!("serving: {e}"))?;
    Ok(())
}

fn ingest(raw: &[String]) -> Result<(), Fail> {
    let (cfg_path, files) = split_args(raw)?;
    if files.is_empty() {
        return Err("ingest needs at least one MARKFILE".to_string().into());
    }
    let c = load_config(&cfg_path)?;
    let r = open_receiver(&c)?;
    let mut refused = false;
    for f in &files {
        let mut b = read_bounded(Path::new(f), MAX_FRAME as u64 + 2)?;
        while b.last().is_some_and(|&x| x == b'\n' || x == b'\r') {
            b.pop();
        }
        let res = RemoteMark::from_request_line(&b)
            .map_err(|e| e.to_string())
            .and_then(|m| {
                r.advance(&m)
                    .map(|a| format!("unit {} seq {}: {a:?}", m.unit, m.seq))
                    .map_err(|e| format!("unit {} seq {}: {e}", m.unit, m.seq))
            });
        match res {
            Ok(m) => println!("{f}: {m}"),
            Err(e) => {
                refused = true;
                println!("{f}: REFUSED: {e}");
            }
        }
    }
    if refused {
        return Err(Fail::Refused);
    }
    Ok(())
}

fn status(raw: &[String]) -> Result<(), Fail> {
    let (cfg_path, rest) = split_args(raw)?;
    if !rest.is_empty() {
        return Err("status takes no positional arguments".to_string().into());
    }
    let c = load_config(&cfg_path)?;
    let mut out = Vec::new();
    for u in unit_keys(&c)? {
        let v = match read_unit_state(&c.state_dir, &u.unit, &*u.verifier) {
            Ok((m, alerts)) => serde_json::json!({
                "unit": u.unit,
                "key_id": u.verifier.key_id(),
                "held_seq": m.as_ref().map(|m| m.seq),
                "chain_id": m.as_ref().map(|m| robodr_blackbox::crypto::to_hex(&m.chain_id)),
                "hash": m.as_ref().map(|m| robodr_blackbox::crypto::to_hex(&m.hash)),
                "alerts": alerts,
            }),
            Err(e) => serde_json::json!({ "unit": u.unit, "unusable": e }),
        };
        out.push(v);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({ "units": out })).unwrap_or_default()
    );
    Ok(())
}
