//! `robodr-blackbox`: key and evidence tooling for the black-box recorder.
//!
//! ```text
//! robodr-blackbox keygen  --out FILE [--key-id ID]
//! robodr-blackbox verify  DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
//!                         [--device ID] [--strict] [--json]
//! robodr-blackbox inspect DIR|SEGMENT [--json] [--limit N]
//! ```
//!
//! - `keygen` writes a new HMAC-SHA256 key file (`robodr-blackbox-key/v1`)
//!   with mode 0600. It refuses to overwrite anything and never writes
//!   through a symlink. It prints the key id, never the secret.
//! - `verify` checks a log directory with every key in the given key or
//!   keyring files (so a log spanning a key rotation verifies). Key files
//!   readable by group or others are refused. `--checkpoint` is a trusted
//!   checkpoint held off the unit; without it the directory's own
//!   `checkpoint.json` is used.
//! - `inspect` lists frames (seq, kind, flags, time, payload) without
//!   checking any signature: it is a viewer, not a verdict.
//!
//! Exit codes: 0 = verified intact (warnings allowed unless `--strict`),
//! 1 = verification failed, 2 = usage, I/O or key error.
//!
//! Secrets are never accepted on the command line (argv is visible to every
//! process through /proc).

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::keys::{KeyFile, Keyring};
use robodr_blackbox::record::{scan_frames, ScanItem};
use robodr_blackbox::store::CHECKPOINT_FILE;
use robodr_blackbox::verify::{read_segments, verify_dir, SegmentData, VerifyOptions};
use robodr_blackbox::Checkpoint;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage:
  robodr-blackbox keygen  --out FILE [--key-id ID]
  robodr-blackbox verify  DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
                          [--device ID] [--strict] [--json]
  robodr-blackbox inspect DIR|SEGMENT [--json] [--limit N]
exit: 0 intact, 1 verification failed, 2 usage/IO/key error";

const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;
const PAYLOAD_PREVIEW: usize = 160;

struct Args {
    positional: Vec<String>,
    opts: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse(raw: &[String], valued: &[&str], flags: &[&str]) -> Result<Self, String> {
        let mut a = Args {
            positional: Vec::new(),
            opts: Vec::new(),
            flags: Vec::new(),
        };
        let mut it = raw.iter();
        while let Some(x) = it.next() {
            if let Some(name) = x.strip_prefix("--") {
                if valued.contains(&name) {
                    let v = it.next().ok_or(format!("--{name} needs a value"))?;
                    a.opts.push((name.to_string(), v.clone()));
                } else if flags.contains(&name) {
                    a.flags.push(name.to_string());
                } else {
                    return Err(format!("unknown option --{name}"));
                }
            } else {
                a.positional.push(x.clone());
            }
        }
        Ok(a)
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn one(&self, name: &str) -> Result<Option<&str>, String> {
        match self.all(name).as_slice() {
            [] => Ok(None),
            [v] => Ok(Some(v)),
            _ => Err(format!("--{name} given more than once")),
        }
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
    fn single_positional(&self, what: &str) -> Result<&str, String> {
        match self.positional.as_slice() {
            [p] => Ok(p),
            [] => Err(format!("missing {what}")),
            _ => Err("too many arguments".into()),
        }
    }
}

enum Fail {
    Usage(String),
    Verify,
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Usage(s)
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let res = match argv.first().map(String::as_str) {
        Some("keygen") => keygen(&argv[1..]),
        Some("verify") => verify(&argv[1..]),
        Some("inspect") => inspect(&argv[1..]),
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(Fail::Usage("missing or unknown subcommand".into())),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Verify) => ExitCode::from(1),
        Err(Fail::Usage(m)) => {
            eprintln!("robodr-blackbox: {m}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn keygen(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["out", "key-id"], &[])?;
    if !a.positional.is_empty() {
        return Err("keygen takes no positional arguments".to_string().into());
    }
    let out = a
        .one("out")?
        .ok_or_else(|| "--out FILE is required".to_string())?;
    let key = KeyFile::generate_hmac(a.one("key-id")?).map_err(|e| e.to_string())?;
    key.write_new(Path::new(out))
        .map_err(|e| format!("{out}: {e}"))?;
    println!("{}", key.key_id);
    Ok(())
}

fn verify(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &["keyring", "checkpoint", "device"],
        &["strict", "json"],
    )?;
    let dir = PathBuf::from(a.single_positional("log directory")?);
    let files = a.all("keyring");
    if files.is_empty() {
        return Err("--keyring FILE is required".to_string().into());
    }
    let mut ring = Keyring::new();
    for f in files {
        ring.load_file(Path::new(f))
            .map_err(|e| format!("{f}: {e}"))?;
    }
    let mut opts = VerifyOptions {
        expected_device_id: a.one("device")?.map(str::to_string),
        ..Default::default()
    };
    if let Some(p) = a.one("checkpoint")? {
        let text = read_bounded(Path::new(p), MAX_CHECKPOINT_BYTES)?;
        opts.checkpoint =
            Some(Checkpoint::from_json(&text).ok_or(format!("{p}: not a checkpoint"))?);
    }
    if !dir.is_dir() {
        return Err(format!("{}: not a directory", dir.display()).into());
    }
    let report = verify_dir(&dir, &ring, &opts).map_err(|e| format!("{}: {e}", dir.display()))?;
    let ok = report.is_intact() && (!a.flag("strict") || report.is_clean());
    if a.flag("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        if let Some(id) = &report.identity {
            println!(
                "chain {} device {} key {} ({})",
                report.chain_id.as_deref().unwrap_or("?"),
                id.device_id,
                id.key_id,
                id.algorithm
            );
        }
        println!(
            "frames {} verified {} seq {:?}..={:?} last seal {:?}",
            report.frames,
            report.verified_records,
            report.first_seq,
            report.last_seq,
            report.last_seal_seq
        );
        println!("keys {}", ring.key_ids().join(", "));
        for f in &report.findings {
            println!("{f}");
        }
        println!(
            "RESULT: {}",
            if !report.is_intact() {
                "TAMPER"
            } else if report.is_clean() {
                "INTACT, CLEAN"
            } else {
                "INTACT, WITH WARNINGS"
            }
        );
    }
    if ok {
        Ok(())
    } else {
        Err(Fail::Verify)
    }
}

fn read_bounded(p: &Path, max: u64) -> Result<String, String> {
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut s = String::new();
    f.take(max + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if s.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", p.display()));
    }
    Ok(s)
}

fn inspect(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["limit"], &["json"])?;
    let path = PathBuf::from(a.single_positional("directory or segment")?);
    let limit = match a.one("limit")? {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| format!("bad --limit {v:?}"))?,
        None => usize::MAX,
    };
    let segments = if path.is_dir() {
        read_segments(&path).map_err(|e| format!("{}: {e}", path.display()))?
    } else {
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        vec![SegmentData {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            bytes,
        }]
    };
    let json = a.flag("json");
    let mut rows = Vec::new();
    let mut shown = 0usize;
    'outer: for seg in &segments {
        let scan = scan_frames(&seg.bytes);
        for it in scan.items {
            if shown == limit {
                break 'outer;
            }
            shown += 1;
            let row = match it {
                ScanItem::Record(sr) => {
                    let r = sr.record;
                    let preview: String = String::from_utf8_lossy(&r.payload)
                        .chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .take(PAYLOAD_PREVIEW)
                        .collect();
                    serde_json::json!({
                        "segment": seg.name, "offset": sr.offset, "seq": r.seq,
                        "kind": r.kind, "critical": r.critical,
                        "wall_ns": r.time.wall_ns, "time_source": format!("{:?}", r.time.source),
                        "hash": to_hex(&r.hash), "hash_ok": r.compute_hash() == r.hash,
                        "payload": preview,
                    })
                }
                ScanItem::Malformed {
                    offset,
                    len,
                    reason,
                } => serde_json::json!({
                    "segment": seg.name, "offset": offset, "malformed": reason, "len": len,
                }),
            };
            if json {
                rows.push(row);
            } else {
                print_row(&row);
            }
        }
        if let Some(t) = scan.tail {
            let row = serde_json::json!({
                "segment": seg.name, "offset": t.offset, "tail": format!("{:?}", t.kind), "len": t.len,
            });
            if json {
                rows.push(row);
            } else {
                print_row(&row);
            }
        }
    }
    let checkpoint = if path.is_dir() {
        read_bounded(&path.join(CHECKPOINT_FILE), MAX_CHECKPOINT_BYTES).ok()
    } else {
        None
    };
    if json {
        let out = serde_json::json!({
            "signatures_checked": false,
            "segments": segments.iter().map(|s| &s.name).collect::<Vec<_>>(),
            "frames": rows,
            "checkpoint": checkpoint.as_deref().and_then(Checkpoint::from_json).map(|c| serde_json::json!({
                "seq": c.seq, "hash": to_hex(&c.hash), "key_id": c.key_id,
            })),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        if let Some(c) = checkpoint.as_deref().and_then(Checkpoint::from_json) {
            println!(
                "{CHECKPOINT_FILE}: seq {} hash {} key {}",
                c.seq,
                to_hex(&c.hash),
                c.key_id
            );
        }
        println!("(signatures not checked; use `verify` for a verdict)");
    }
    Ok(())
}

fn print_row(v: &serde_json::Value) {
    let g = |k: &str| v.get(k).map(|x| x.to_string()).unwrap_or_default();
    if v.get("seq").is_some() {
        println!(
            "{}+{} seq {} {} {}{} wall_ns {} {} {}",
            g("segment").trim_matches('"'),
            g("offset"),
            g("seq"),
            g("kind").trim_matches('"'),
            if v["critical"] == true {
                "critical "
            } else {
                ""
            },
            if v["hash_ok"] == true {
                ""
            } else {
                "HASH-MISMATCH "
            },
            g("wall_ns"),
            g("time_source").trim_matches('"'),
            v["payload"].as_str().unwrap_or("")
        );
    } else {
        println!("{v}");
    }
}
