//! `robodr-setup`: first-boot setup of a RoboDR unit (sales-readiness T68).
//! See `man robodr-setup` (man/robodr-setup.8) and `robodr_ops::setup`.

#![forbid(unsafe_code)]

use robodr_ops::args::{argv, Args};
use robodr_ops::exec::Host;
use robodr_ops::preflight::{self, Check, Level, Probe};
use robodr_ops::setup::{self, ConfigRequest, KeyKind, Role};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
usage:
  robodr-setup preflight    [--json] [--min-free-mib N] [--state-dir DIR] [--ignore-check ID]...
  robodr-setup keys         --unit-id ID [--role ROLE] [--key KIND]... [--keys-dir DIR]
  robodr-setup config       --role ROLE --unit-id ID [--site SITE] [--interface IF]...
                            [--examples DIR] [--out FILE]
  robodr-setup fingerprints [--keys-dir DIR] [--json]
  robodr-setup init         --role ROLE --unit-id ID [--site SITE] [--interface IF]...
                            [--key KIND]... [--ignore-check ID]... [--json]
  common: [--root DIR]   operate on the file tree under DIR (image staging, tests)

ROLE: robot | unitree-edu | unitree-sensor-box | soc-relay
KIND: blackbox | finding | uplink | diode   (default: blackbox; soc-relay: uplink)
Defaults: --keys-dir /etc/robodr/keys, --examples /usr/share/doc/robodr/examples,
          --out /etc/robodr/agentd.json, --state-dir /var/lib/robodr, --min-free-mib 2048.
init = preflight (stops on FAIL) + keys + config + fingerprints. Nothing existing is
ever overwritten. Exit: 0 ok, 1 a check failed or an error, 2 usage.";

enum Fail {
    Usage(String),
    Run(String),
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Usage(s)
    }
}

fn main() -> ExitCode {
    let raw = match argv() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("robodr-setup: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let res = match raw.first().map(String::as_str) {
        Some("preflight") => cmd_preflight(raw.get(1..).unwrap_or_default()),
        Some("keys") => cmd_keys(raw.get(1..).unwrap_or_default()),
        Some("config") => cmd_config(raw.get(1..).unwrap_or_default()),
        Some("fingerprints") => cmd_fingerprints(raw.get(1..).unwrap_or_default()),
        Some("init") => cmd_init(raw.get(1..).unwrap_or_default()),
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("-V" | "--version") => {
            println!("robodr-setup {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => Err(Fail::Usage("a subcommand is required".into())),
    };
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(Fail::Run(e)) => {
            eprintln!("robodr-setup: {e}");
            ExitCode::from(1)
        }
        Err(Fail::Usage(e)) => {
            eprintln!("robodr-setup: {e}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn root(a: &Args) -> Result<PathBuf, String> {
    let r = PathBuf::from(a.one("root")?.unwrap_or("/"));
    if !r.is_absolute() {
        return Err("--root must be an absolute path".into());
    }
    Ok(r)
}

fn no_positional(a: &Args) -> Result<(), String> {
    match a.positional.first() {
        Some(p) => Err(format!("unexpected argument {p:?}")),
        None => Ok(()),
    }
}

fn abs(a: &Args, name: &str, default: &str) -> Result<String, String> {
    let v = a.one(name)?.unwrap_or(default).to_string();
    if !v.starts_with('/') {
        return Err(format!("--{name} must be an absolute path"));
    }
    Ok(v)
}

/// Run the preflight; `Ok(passed)`. Ignored checks are downgraded to WARN
/// and say so (`keys.dir` cannot be ignored).
fn preflight_checks(a: &Args, root: &Path) -> Result<Vec<Check>, String> {
    let host = Host {
        timeout: std::time::Duration::from_secs(15),
        cap: 1 << 20,
    };
    let probe = Probe {
        root: root.to_path_buf(),
        runner: &host,
        now: std::time::SystemTime::now(),
    };
    let opts = preflight::Options {
        variant: preflight::detect_variant(root),
        state_dir: abs(a, "state-dir", "/var/lib/robodr")?,
        min_free_mib: a.u64_or("min-free-mib", 2048)?,
        ..Default::default()
    };
    let ignored: Vec<&str> = a.all("ignore-check").collect();
    if ignored.contains(&"keys.dir") {
        return Err("--ignore-check keys.dir: the key directory check cannot be ignored".into());
    }
    let mut checks = preflight::run(&probe, &opts);
    for id in &ignored {
        if !checks.iter().any(|c| c.id == *id) {
            return Err(format!("--ignore-check {id:?}: no such check"));
        }
    }
    for c in &mut checks {
        if c.level == Level::Fail && ignored.contains(&c.id) {
            c.level = Level::Warn;
            c.detail = format!("IGNORED by the operator (--ignore-check): {}", c.detail);
        }
    }
    Ok(checks)
}

fn print_checks(checks: &[Check]) {
    for c in checks {
        println!("[{}] {:<10} {}", c.level.tag(), c.id, c.detail);
    }
}

fn cmd_preflight(raw: &[String]) -> Result<bool, Fail> {
    let a = Args::parse(
        raw,
        &["root", "min-free-mib", "state-dir", "ignore-check"],
        &["json"],
    )?;
    no_positional(&a)?;
    let root = root(&a)?;
    let checks = preflight_checks(&a, &root)?;
    let pass = preflight::worst(&checks) < Level::Fail;
    if a.flag("json") {
        let v = serde_json::json!({
            "format": "robodr-preflight/1",
            "result": if pass { "pass" } else { "fail" },
            "checks": checks,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Fail::Run(e.to_string()))?
        );
    } else {
        print_checks(&checks);
        println!(
            "preflight: {}",
            if pass {
                "PASS"
            } else {
                "FAIL (fix the FAIL lines before starting RoboDR)"
            }
        );
    }
    Ok(pass)
}

fn key_kinds(a: &Args, role: Role) -> Result<Vec<KeyKind>, String> {
    let mut kinds = setup::default_keys(role);
    for k in a.all("key") {
        let k = KeyKind::parse(k)?;
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    }
    Ok(kinds)
}

fn do_keys(a: &Args, root: &Path, role: Role) -> Result<Vec<setup::KeyOutcome>, Fail> {
    let unit = a
        .one("unit-id")?
        .ok_or_else(|| "--unit-id is required".to_string())?;
    let keys_dir = abs(a, "keys-dir", "/etc/robodr/keys")?;
    let kinds = key_kinds(a, role)?;
    setup::generate_keys(root, &keys_dir, &kinds, unit).map_err(Fail::Run)
}

fn print_keys(out: &[setup::KeyOutcome]) {
    for k in out {
        println!(
            "key {:<9} {:<7} {} ({})",
            k.kind.name(),
            k.action,
            k.path,
            k.key_id
        );
    }
}

fn role(a: &Args, required: bool) -> Result<Role, String> {
    match a.one("role")? {
        Some(r) => Role::parse(r),
        None if required => Err("--role is required".into()),
        None => Ok(Role::Robot),
    }
}

fn cmd_keys(raw: &[String]) -> Result<bool, Fail> {
    let a = Args::parse(raw, &["root", "unit-id", "role", "key", "keys-dir"], &[])?;
    no_positional(&a)?;
    let root = root(&a)?;
    let out = do_keys(&a, &root, role(&a, false)?)?;
    print_keys(&out);
    Ok(true)
}

fn do_config(
    a: &Args,
    root: &Path,
    role: Role,
) -> Result<Option<(String, bool, Vec<String>)>, Fail> {
    let Some(example) = role.agentd_example() else {
        return Ok(None);
    };
    let unit = a
        .one("unit-id")?
        .ok_or_else(|| "--unit-id is required".to_string())?;
    let examples = abs(a, "examples", "/usr/share/doc/robodr/examples")?;
    let out = abs(a, "out", "/etc/robodr/agentd.json")?;
    let src = robodr_ops::rooted(root, &format!("{examples}/{example}"));
    let text = std::fs::read_to_string(&src)
        .map_err(|e| Fail::Run(format!("{examples}/{example}: {e}")))?;
    let req = ConfigRequest {
        role,
        unit_id: unit.to_string(),
        site: a.one("site")?.map(str::to_string),
        interfaces: a.all("interface").map(str::to_string).collect(),
    };
    let (v, review) = setup::render_config(&text, &req).map_err(Fail::Run)?;
    let body = serde_json::to_string_pretty(&v).map_err(|e| Fail::Run(e.to_string()))?;
    let created = setup::write_config(root, &out, &body).map_err(Fail::Run)?;
    Ok(Some((out, created, review)))
}

fn print_config(r: &Option<(String, bool, Vec<String>)>) {
    match r {
        None => println!("config: none for this role (no robodr-agentd)"),
        Some((out, created, review)) => {
            if *created {
                println!("config: wrote {out} (0640, group robodr)");
            } else {
                println!("config: {out} exists, kept (never overwritten)");
            }
            for p in review {
                println!("config: review {p} (still an example value)");
            }
            println!(
                "config: check it with: robodr-agentd --config {out} --check-config \
                 (needs the commissioned profile, its trust file and the response policy)"
            );
        }
    }
}

fn cmd_config(raw: &[String]) -> Result<bool, Fail> {
    let a = Args::parse(
        raw,
        &[
            "root",
            "role",
            "unit-id",
            "site",
            "interface",
            "examples",
            "out",
        ],
        &[],
    )?;
    no_positional(&a)?;
    let root = root(&a)?;
    let r = do_config(&a, &root, role(&a, true)?)?;
    print_config(&r);
    Ok(true)
}

fn print_fingerprints(fps: &[setup::Fingerprint]) {
    for f in fps {
        println!(
            "{}\n  key id      {}\n  algorithm   {}\n  device      {}\n  key sha256  {}\n  file sha256 {}",
            f.file,
            f.key_id,
            f.algorithm,
            f.device_id.as_deref().unwrap_or("(not bound)"),
            f.key_sha256,
            f.file_sha256
        );
    }
    if fps.is_empty() {
        println!("no public keys (*.pub)");
    } else {
        println!(
            "Register these with the SOC over a channel you trust, and copy only the .pub files."
        );
    }
}

fn cmd_fingerprints(raw: &[String]) -> Result<bool, Fail> {
    let a = Args::parse(raw, &["root", "keys-dir"], &["json"])?;
    no_positional(&a)?;
    let root = root(&a)?;
    let keys_dir = abs(&a, "keys-dir", "/etc/robodr/keys")?;
    let fps = setup::fingerprints(&root, &keys_dir).map_err(Fail::Run)?;
    if a.flag("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&fps).map_err(|e| Fail::Run(e.to_string()))?
        );
    } else {
        print_fingerprints(&fps);
    }
    Ok(true)
}

fn cmd_init(raw: &[String]) -> Result<bool, Fail> {
    let a = Args::parse(
        raw,
        &[
            "root",
            "role",
            "unit-id",
            "site",
            "interface",
            "key",
            "keys-dir",
            "examples",
            "out",
            "min-free-mib",
            "state-dir",
            "ignore-check",
        ],
        &["json"],
    )?;
    no_positional(&a)?;
    let root = root(&a)?;
    let role = role(&a, true)?;
    let unit = a
        .one("unit-id")?
        .ok_or_else(|| "--unit-id is required".to_string())?;
    setup::check_unit_id(unit)?;
    let checks = preflight_checks(&a, &root)?;
    let pass = preflight::worst(&checks) < Level::Fail;
    if !a.flag("json") {
        print_checks(&checks);
    }
    if !pass {
        if a.flag("json") {
            let v = serde_json::json!({
                "format": "robodr-setup/1", "result": "preflight_failed", "checks": checks,
            });
            println!("{v}");
        } else {
            println!("init: preflight FAILED; nothing was generated or written");
        }
        return Ok(false);
    }
    let keys = do_keys(&a, &root, role)?;
    let cfg = do_config(&a, &root, role)?;
    let keys_dir = abs(&a, "keys-dir", "/etc/robodr/keys")?;
    let fps = setup::fingerprints(&root, &keys_dir).map_err(Fail::Run)?;
    if a.flag("json") {
        let v = serde_json::json!({
            "format": "robodr-setup/1",
            "result": "ok",
            "role": role,
            "unit_id": unit,
            "checks": checks,
            "keys": keys,
            "config": cfg.as_ref().map(|(p, c, r)| serde_json::json!({
                "path": p, "action": if *c { "created" } else { "kept" }, "review": r })),
            "fingerprints": fps,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Fail::Run(e.to_string()))?
        );
    } else {
        print_keys(&keys);
        print_config(&cfg);
        print_fingerprints(&fps);
        println!(
            "init: done. Next: install the commissioned profile (OPERATIONS.md section 5), \
             then systemctl enable --now robodr-agentd"
        );
    }
    Ok(true)
}
