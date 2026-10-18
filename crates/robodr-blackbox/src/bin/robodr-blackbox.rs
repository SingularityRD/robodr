//! `robodr-blackbox`: key and evidence tooling for the black-box recorder.
//!
//! ```text
//! robodr-blackbox keygen     --out FILE [--alg ed25519|hmac] [--key-id ID] [--pub-out FILE]
//!                            [--device ID]
//! robodr-blackbox export-pub KEYFILE [--out FILE]
//! robodr-blackbox verify     DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
//!                            [--device ID] [--allow-mixed-algorithms] [--strict] [--json]
//! robodr-blackbox inspect    DIR|SEGMENT [--json] [--limit N]
//! robodr-blackbox tpm-anchor-init  --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
//!                            [--owner-auth-file FILE] [--index-auth-file FILE]
//! robodr-blackbox tpm-anchor-check --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
//!                            [--index-auth-file FILE]
//! ```
//!
//! - `keygen` writes a new key. Default `--alg ed25519`: the secret seed
//!   file (`robodr-blackbox-key/v2`, mode 0600) at `--out` and the public
//!   key file (mode 0644, safe to distribute) at `--pub-out`, default
//!   `<out>.pub`. `--alg hmac` writes a legacy symmetric HMAC-SHA256 key
//!   (`robodr-blackbox-key/v1`, 0600, no public half) and warns. Nothing
//!   is ever overwritten or written through a symlink; if either target
//!   exists nothing is written. It prints the key id, never the secret.
//!   `--device ID` binds the key to that unit (`device_id` in both files):
//!   verifiers then accept it only for chains of that device.
//! - `export-pub` writes (or prints) the public key file of an Ed25519
//!   secret key file. HMAC keys have no public half and are refused.
//! - `verify` checks a log directory with every key in the given key or
//!   keyring files (so a log spanning a key rotation verifies). Public key
//!   files are accepted whatever their mode; files holding a secret are
//!   refused if group or others can access them or if they are owned by
//!   another user (root excepted). `--checkpoint` is a trusted checkpoint
//!   held off the unit; without it the directory's own `checkpoint.json`
//!   is used. Each record is checked under the key its chain names (see
//!   `robodr_blackbox::verify`), never under "any key given". Mixing HMAC
//!   and Ed25519 keys is refused unless `--allow-mixed-algorithms` (needed
//!   only for a log that rotated from a legacy HMAC key to Ed25519).
//! - `inspect` lists frames (seq, kind, flags, time, payload) without
//!   checking any signature: it is a viewer, not a verdict.
//! - `tpm-anchor-init` provisions the TPM 2.0 NV counter behind
//!   `robodr_blackbox::TpmNvCounterAnchor`: it defines `--index` under the
//!   owner hierarchy with `authread|authwrite|nt=counter|no_da`, size 8
//!   (`tpm2_nvdefine`), and refuses an index that already exists. The
//!   counter stays unwritten until the recorder's first mark. Default TCTI
//!   `device:/dev/tpmrm0`, tools from `/usr/bin`. Authorization values are
//!   read from files (`file:` for tpm2-tools), never from argv.
//! - `tpm-anchor-check` reads the index's public area and value and exits
//!   1 if it is not a counter.
//!
//! Exit codes: 0 = verified intact (warnings allowed unless `--strict`),
//! 1 = verification failed, 2 = usage, I/O or key error.
//!
//! Secrets are never accepted on the command line (argv is visible to every
//! process through /proc).

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::keys::{public_key_path, KeyFile, Keyring};
use robodr_blackbox::record::{scan_frames, ScanItem};
use robodr_blackbox::store::CHECKPOINT_FILE;
use robodr_blackbox::tpm_anchor::{self, parse_nv_index, NvCounter, Tpm2Tools};
use robodr_blackbox::verify::{read_segments, verify_dir, SegmentData, VerifyOptions};
use robodr_blackbox::Checkpoint;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  robodr-blackbox keygen     --out FILE [--alg ed25519|hmac] [--key-id ID] [--pub-out FILE]
                             [--device ID]
  robodr-blackbox export-pub KEYFILE [--out FILE]
  robodr-blackbox verify     DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
                             [--device ID] [--allow-mixed-algorithms] [--strict] [--json]
  robodr-blackbox inspect    DIR|SEGMENT [--json] [--limit N]
  robodr-blackbox tpm-anchor-init  --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
                             [--owner-auth-file FILE] [--index-auth-file FILE]
  robodr-blackbox tpm-anchor-check --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
                             [--index-auth-file FILE]
keygen defaults to ed25519 (secret FILE, 0600; public FILE.pub, safe to share).
--keyring accepts secret key files (0600, own user or root) and public key
files (any mode).
exit: 0 intact, 1 verification failed, 2 usage/IO/key error";

const HMAC_WARNING: &str = "warning: hmac-sha256 is the legacy symmetric placeholder: every \
holder of this key can also forge evidence. Use ed25519 for production.";

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
    // args_os: std::env::args() panics on an argument that is not valid
    // Unicode; that is a usage error (exit 2).
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("robodr-blackbox: an argument is not valid UTF-8\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let res = match argv.first().map(String::as_str) {
        Some("keygen") => keygen(&argv[1..]),
        Some("export-pub") => export_pub(&argv[1..]),
        Some("verify") => verify(&argv[1..]),
        Some("inspect") => inspect(&argv[1..]),
        Some("tpm-anchor-init") => tpm_anchor_init(&argv[1..]),
        Some("tpm-anchor-check") => tpm_anchor_check(&argv[1..]),
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
    let a = Args::parse(raw, &["out", "key-id", "alg", "pub-out", "device"], &[])?;
    if !a.positional.is_empty() {
        return Err("keygen takes no positional arguments".to_string().into());
    }
    let out = Path::new(
        a.one("out")?
            .ok_or_else(|| "--out FILE is required".to_string())?,
    );
    let alg = match a.one("alg")?.unwrap_or("ed25519") {
        "ed25519" => "ed25519",
        "hmac" | "hmac-sha256" => "hmac-sha256",
        other => return Err(format!("--alg {other:?}: expected ed25519 or hmac").into()),
    };
    let pub_out = match (alg, a.one("pub-out")?) {
        ("ed25519", Some(p)) => Some(PathBuf::from(p)),
        ("ed25519", None) => Some(public_key_path(out)),
        (_, Some(_)) => {
            return Err("--pub-out: an hmac key has no public half"
                .to_string()
                .into())
        }
        (_, None) => None,
    };
    if let Some(p) = &pub_out {
        if p == out {
            return Err("--pub-out must differ from --out".to_string().into());
        }
        // Refuse before writing anything, so a half-made pair never exists.
        if std::fs::symlink_metadata(p).is_ok() {
            return Err(format!("{}: refusing to overwrite an existing file", p.display()).into());
        }
    }
    let device = a.one("device")?;
    let key = KeyFile::generate(alg, a.one("key-id")?)
        .and_then(|k| k.with_device_id(device))
        .map_err(|e| e.to_string())?;
    key.write_new(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    if let Some(p) = &pub_out {
        let res = key
            .to_public()
            .and_then(|pk| pk.write_new(p))
            .map_err(|e| format!("{}: {e}", p.display()));
        if let Err(e) = res {
            // Never leave a secret without its public half (and no stray
            // secret either): undo the secret file.
            let _ = std::fs::remove_file(out);
            return Err(e.into());
        }
        eprintln!(
            "wrote secret key {} (mode 0600, keep on the unit) and public key {} (safe to distribute)",
            out.display(),
            p.display()
        );
    } else {
        eprintln!("{HMAC_WARNING}");
    }
    println!("{}", key.key_id);
    Ok(())
}

fn export_pub(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["out"], &[])?;
    let src = a.single_positional("key file")?;
    let key = KeyFile::load(Path::new(src)).map_err(|e| format!("{src}: {e}"))?;
    let public = key.to_public().map_err(|e| format!("{src}: {e}"))?;
    match a.one("out")? {
        Some(out) => {
            public
                .write_new(Path::new(out))
                .map_err(|e| format!("{out}: {e}"))?;
            println!("{}", public.key_id);
        }
        None => print!("{}", public.to_json()),
    }
    Ok(())
}

fn verify(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &["keyring", "checkpoint", "device"],
        &["strict", "json", "allow-mixed-algorithms"],
    )?;
    let dir = PathBuf::from(a.single_positional("log directory")?);
    let files = a.all("keyring");
    if files.is_empty() {
        return Err("--keyring FILE is required".to_string().into());
    }
    let mut ring = Keyring::new();
    ring.set_allow_mixed_algorithms(a.flag("allow-mixed-algorithms"));
    for f in files {
        ring.load_file(Path::new(f))
            .map_err(|e| format!("{f}: {e}"))?;
    }
    let symmetric = ring.symmetric_key_ids();
    if !symmetric.is_empty() {
        eprintln!(
            "warning: symmetric (hmac-sha256) key(s) {}: anyone holding them can also forge",
            symmetric.join(", ")
        );
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

/// The counter named by `--index`, reached with `--tcti` / `--tools-dir`.
fn tpm_counter(a: &Args) -> Result<NvCounter, String> {
    if !a.positional.is_empty() {
        return Err("tpm-anchor commands take no positional arguments".into());
    }
    let index = parse_nv_index(a.one("index")?.ok_or("--index 0x01XXXXXX is required")?)?;
    let tools = Tpm2Tools::new(
        a.one("tools-dir")?.unwrap_or(tpm_anchor::DEFAULT_TOOLS_DIR),
        a.one("tcti")?.unwrap_or(tpm_anchor::DEFAULT_TCTI),
        Duration::from_secs(30),
    )?;
    let auth = abs_file(a.one("index-auth-file")?, "--index-auth-file")?;
    Ok(NvCounter::new(index, auth, Box::new(tools)))
}

fn abs_file(v: Option<&str>, what: &str) -> Result<Option<PathBuf>, String> {
    match v.map(PathBuf::from) {
        Some(p) if !p.is_absolute() => Err(format!("{what} must be an absolute path")),
        Some(p) if !p.is_file() => Err(format!("{what} {}: not a file", p.display())),
        other => Ok(other),
    }
}

fn tpm_anchor_init(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &[
            "index",
            "tcti",
            "tools-dir",
            "owner-auth-file",
            "index-auth-file",
        ],
        &[],
    )?;
    let c = tpm_counter(&a)?;
    let owner = abs_file(a.one("owner-auth-file")?, "--owner-auth-file")?;
    let index_auth = abs_file(a.one("index-auth-file")?, "--index-auth-file")?;
    let idx = tpm_anchor::format_nv_index(c.index());
    if let Ok(p) = c.read_public() {
        return Err(format!(
            "NV index {idx} is already defined (attributes {:#010x}, counter: {}); refusing to \
             touch it (undefine it first with tpm2_nvundefine if it is really unused)",
            p.attributes,
            p.is_counter()
        )
        .into());
    }
    c.define(owner.as_deref(), index_auth.as_deref())?;
    let p = c.check_counter()?;
    eprintln!(
        "defined NV counter {idx} ({}, attributes {:#010x}); it stays unwritten until the \
         recorder's first mark",
        tpm_anchor::PROVISION_ATTRIBUTES,
        p.attributes
    );
    println!("{idx}");
    Ok(())
}

fn tpm_anchor_check(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["index", "tcti", "tools-dir", "index-auth-file"], &[])?;
    let c = tpm_counter(&a)?;
    let idx = tpm_anchor::format_nv_index(c.index());
    let p = c.read_public()?;
    if !p.is_counter() || p.size != 8 {
        eprintln!(
            "NV index {idx} is not a counter (attributes {:#010x}, size {})",
            p.attributes, p.size
        );
        return Err(Fail::Verify);
    }
    let value = if p.written() {
        c.read()?.to_string()
    } else {
        "unwritten".to_string()
    };
    println!(
        "{}",
        serde_json::json!({
            "nv_index": idx,
            "attributes": format!("{:#010x}", p.attributes),
            "counter": true,
            "orderly": p.attributes & tpm_anchor::attr::ORDERLY != 0,
            "written": p.written(),
            "value": value,
        })
    );
    Ok(())
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
