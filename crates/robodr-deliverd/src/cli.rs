//! `robodr-deliverd` and `robodr-safety-replay` command lines.

use crate::clock::SystemClock;
use crate::config::Config;
use crate::engine::{confirm_path, Engine};
use crate::state::StateFile;
use robodr_diode::cli::{argv, is_version_request, parse_args_with_switches, Args};
use std::path::Path;
use std::time::{Duration, Instant};

pub const USAGE: &str = "\
usage:
  robodr-deliverd run          --config FILE
  robodr-deliverd once         --config FILE
  robodr-deliverd check-config --config FILE
  robodr-deliverd init-anchor  --config FILE --trust TRUST.json
  robodr-deliverd reanchor     --config FILE --trust TRUST.json
  robodr-deliverd status       --config FILE
  robodr-deliverd confirm      --config FILE --deployment DIGEST --package NAME
  robodr-deliverd --version

The on-unit delivery agent (docs/SECURE-DELIVERY.md §4.2, §6; man
robodr-deliverd(8)). It imports per-unit media packs put under media_dir
through the verified-copy path, installs files / config / deb /
robodr-rules RPKs only while agentd's live safety state is idle or
safe_state_active, judges the RPK's health checks, rolls back
automatically, keeps anti-rollback floors, records every step in its
black box and spools robot.deliver.* findings.

run           loop every interval_ms until SIGTERM / SIGINT (systemd).
once          one pass (prints what it did as JSON; exit 0, or 1 on error).
check-config  validate the configuration and exit.
init-anchor   create the unit's trust anchor from a trust file accepted
              under the pinned roots and site (once, at enrolment).
reanchor      after a lost state file the agent locks itself (no import,
              no install) when its signed high-water record is gone too;
              an operator presents the site's current trust file (the
              anchor or a newer rotation; a new anchor if none is left)
              and the lock is lifted. Stop the service first.
status        print the state (installed versions, floors, deployment).
confirm       record a local operator's confirmation for an RPK that
              requires one (install.requires_operator_present).

Exit codes: 0 ok, 1 refused or error, 2 usage.";

pub const REPLAY_USAGE: &str = "\
usage:
  robodr-safety-replay --socket PATH --file REPORTS.jsonl [--repeat-ms N] [--hold-ms N]
                       [--connect-timeout-ms N] [--check]

Replays recorded safety reports ({\"at_ms\":N,\"state\":\"...\"} per line)
into agentd's safety_feed socket in real time, repeating each state every
--repeat-ms (default 200) until the next one and the last for --hold-ms
(default 0). --check only parses and prints the schedule length. A test
and demo tool: it decides the safety state agentd acts on.

Exit codes: 0 ok, 1 error, 2 usage.";

fn usage(msg: &str, text: &str, prog: &str) -> i32 {
    eprintln!("{prog}: {msg}\n\n{text}");
    2
}

fn print(v: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
}

/// Entry point of `robodr-deliverd`.
pub fn main_deliverd() -> i32 {
    match argv() {
        Ok(a) => run_deliverd(a),
        Err(e) => usage(&e, USAGE, "robodr-deliverd"),
    }
}

/// Run one `robodr-deliverd` command line (without the program name).
pub fn run_deliverd(args: Vec<String>) -> i32 {
    if is_version_request(&args) {
        println!("robodr-deliverd {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if matches!(args.as_slice(), [a] if a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }
    let mut it = args.into_iter();
    let Some(cmd) = it.next() else {
        return usage("missing command", USAGE, "robodr-deliverd");
    };
    let rest: Vec<String> = it.collect();
    let known: &[&str] = match cmd.as_str() {
        "init-anchor" | "reanchor" => &["config", "trust"],
        "confirm" => &["config", "deployment", "package"],
        "run" | "once" | "check-config" | "status" => &["config"],
        other => {
            return usage(
                &format!("unknown command {other:?}"),
                USAGE,
                "robodr-deliverd",
            )
        }
    };
    let a = match parse_args_with_switches(rest, known, &[]) {
        Ok(a) => a,
        Err(e) => return usage(&e, USAGE, "robodr-deliverd"),
    };
    let cfg = match a.req("config") {
        Ok(p) => match Config::load(Path::new(p)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("robodr-deliverd: configuration: {e}");
                return 2;
            }
        },
        Err(e) => return usage(&e, USAGE, "robodr-deliverd"),
    };
    let r = match cmd.as_str() {
        "check-config" => {
            println!("robodr-deliverd: configuration ok");
            Ok(())
        }
        "init-anchor" => init_anchor(&cfg, &a),
        "reanchor" => reanchor(cfg, &a),
        "status" => status(&cfg),
        "confirm" => confirm(&cfg, &a),
        "once" => once(cfg),
        _ => run_loop(cfg),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("robodr-deliverd: {e}");
            1
        }
    }
}

fn init_anchor(cfg: &Config, a: &Args) -> Result<(), String> {
    let trust = a.req("trust")?;
    let now = crate::clock::Clock::now_s(&SystemClock)?;
    crate::fsx::ensure_dir(&cfg.state_dir, 0o700).map_err(|e| e.to_string())?;
    let t = robodr_release::ops::init_anchor(
        Path::new(trust),
        &cfg.anchor_path(),
        &cfg.trust.roots,
        &cfg.unit.site,
        now,
    )
    .map_err(|e| e.to_string())?;
    print(serde_json::json!({
        "anchor": cfg.anchor_path(),
        "site": t.file().site,
        "version": t.file().version,
        "digest": t.digest,
        "expires_at": t.file().expires_at,
        "unit_ring": t.ring_of_unit(&cfg.unit.id),
    }));
    Ok(())
}

fn reanchor(cfg: Config, a: &Args) -> Result<(), String> {
    let trust = a.req("trust")?.to_string();
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let v = e.reanchor(Path::new(&trust)).map_err(|e| e.0);
    let closed = e.close().map_err(|e| e.0);
    print(v?);
    closed
}

fn status(cfg: &Config) -> Result<(), String> {
    let mut f = StateFile::new(&cfg.state_path());
    let s = f.load()?;
    print(serde_json::to_value(&s).map_err(|e| e.to_string())?);
    Ok(())
}

fn confirm(cfg: &Config, a: &Args) -> Result<(), String> {
    let digest = a.req("deployment")?;
    let name = a.req("package")?;
    if !robodr_pkg::common::is_hex64(digest) || !robodr_pkg::common::is_pkg_name(name) {
        return Err(
            "--deployment is the deployment digest (64 hex), --package a package name".into(),
        );
    }
    let s = StateFile::new(&cfg.state_path())
        .load()?
        .ok_or_else(|| "no state yet".to_string())?;
    let d = s
        .deployment
        .as_ref()
        .filter(|d| d.digest == digest)
        .ok_or_else(|| "that is not the deployment being installed (see `status`)".to_string())?;
    if !d.items.iter().any(|i| i.name == name) {
        return Err(format!("deployment has no item {name}"));
    }
    let dir = cfg.state_dir.join("confirm");
    crate::fsx::ensure_dir(&dir, 0o700).map_err(|e| e.to_string())?;
    let p = confirm_path(cfg, digest, name);
    let now = crate::clock::Clock::now_s(&SystemClock)?;
    let body = serde_json::json!({"deployment": digest, "package": name, "at": now});
    crate::fsx::write_new(&p, body.to_string().as_bytes(), 0o600)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    println!("robodr-deliverd: confirmation recorded for {name}");
    Ok(())
}

fn report_json(r: &crate::engine::TickReport) -> serde_json::Value {
    serde_json::json!({
        "imported": r.imported, "refused": r.refused, "installed": r.installed,
        "deferred": r.deferred, "rolled_back": r.rolled_back, "blocked": r.blocked,
        "recovered": r.recovered, "stale": r.stale,
    })
}

fn once(cfg: Config) -> Result<(), String> {
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let r = e.tick().map_err(|e| e.0);
    let closed = e.close().map_err(|e| e.0);
    let r = r?;
    closed?;
    print(report_json(&r));
    Ok(())
}

fn run_loop(cfg: Config) -> Result<(), String> {
    robodr_agentd::signal::install().map_err(|e| format!("signal handler: {e}"))?;
    let interval = Duration::from_millis(cfg.interval_ms);
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let notifier = robodr_agentd::notify::Notifier::from_env();
    notifier.notify("READY=1");
    let mut res = Ok(());
    while !robodr_agentd::signal::requested() {
        match e.tick() {
            Ok(r) => {
                let v = report_json(&r);
                let busy = !(r.imported.is_empty()
                    && r.refused.is_empty()
                    && r.installed.is_empty()
                    && r.rolled_back.is_empty()
                    && r.blocked.is_empty()
                    && r.recovered.is_empty());
                if busy {
                    println!("{v}");
                }
            }
            Err(err) => {
                // An evidence or state write failed: stop (systemd restarts
                // the unit; the intent in the state file is resumed).
                res = Err(err.0);
                break;
            }
        }
        let until = Instant::now() + interval;
        while Instant::now() < until && !robodr_agentd::signal::requested() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    notifier.notify("STOPPING=1");
    let closed = e.close().map_err(|e| e.0);
    res?;
    closed
}

/// Entry point of `robodr-safety-replay`.
pub fn main_replay() -> i32 {
    match argv() {
        Ok(a) => run_replay(a),
        Err(e) => usage(&e, REPLAY_USAGE, "robodr-safety-replay"),
    }
}

/// Run one `robodr-safety-replay` command line.
pub fn run_replay(args: Vec<String>) -> i32 {
    if is_version_request(&args) {
        println!("robodr-safety-replay {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let a = match parse_args_with_switches(
        args,
        &[
            "socket",
            "file",
            "repeat-ms",
            "hold-ms",
            "connect-timeout-ms",
        ],
        &["check"],
    ) {
        Ok(a) => a,
        Err(e) if e == "help" => {
            println!("{REPLAY_USAGE}");
            return 0;
        }
        Err(e) => return usage(&e, REPLAY_USAGE, "robodr-safety-replay"),
    };
    let r = (|| -> Result<Result<String, String>, String> {
        let file = a.req("file")?;
        let repeat = a.num::<u64>("repeat-ms")?.unwrap_or(200);
        let hold = a.num::<u64>("hold-ms")?.unwrap_or(0);
        let wait = a.num::<u64>("connect-timeout-ms")?.unwrap_or(5000);
        let check = a.flag("check");
        let socket = if check {
            None
        } else {
            Some(a.req("socket")?.to_string())
        };
        Ok((|| {
            let bytes =
                robodr_release::fsio::read_capped(Path::new(file), crate::replay::MAX_FILE_BYTES)
                    .map_err(|e| e.to_string())?;
            let reports = crate::replay::parse(&bytes)?;
            let sched = crate::replay::schedule(&reports, repeat, hold)?;
            match socket {
                None => Ok(format!(
                    "{} records, {} lines to send",
                    reports.len(),
                    sched.len()
                )),
                Some(s) => crate::replay::run(Path::new(&s), &sched, Duration::from_millis(wait))
                    .map(|n| format!("{n} lines sent")),
            }
        })())
    })();
    match r {
        Err(e) => usage(&e, REPLAY_USAGE, "robodr-safety-replay"),
        Ok(Err(e)) => {
            eprintln!("robodr-safety-replay: {e}");
            1
        }
        Ok(Ok(msg)) => {
            println!("robodr-safety-replay: {msg}");
            0
        }
    }
}
