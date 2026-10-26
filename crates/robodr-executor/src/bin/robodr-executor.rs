//! `robodr-executor`: the executor process (see the crate docs).
//!
//! ```text
//! robodr-executor --config /etc/robodr/executor.json            run (systemd unit)
//! robodr-executor --config /etc/robodr/executor.json --check-config
//! robodr-executor status --config /etc/robodr/executor.json     print the journal (read-only)
//! robodr-executor revert-all --config /etc/robodr/executor.json [--reason TEXT]
//! robodr-executor keygen --out /etc/robodr/keys/executor.key
//! ```
//!
//! Exit 0 clean stop, 1 runtime failure, 2 usage / configuration error.
//! The process holds no state outside its journal: a stop or crash at any
//! point is recovered by the reconciliation at the next start, so it has no
//! signal handler (SIGTERM ends it like a crash would, safely).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use robodr_executor::config::{self, ExecutorConfig, Resolved};
use robodr_executor::engine::Engine;
use robodr_executor::nft::NftCommand;
use robodr_executor::proto::{self, Key};
use robodr_executor::server;

const USAGE: &str = "usage: robodr-executor --config FILE [--check-config]\n       \
                     robodr-executor status --config FILE\n       \
                     robodr-executor revert-all --config FILE [--reason TEXT]\n       \
                     robodr-executor keygen --out FILE\n       \
                     robodr-executor --version";

fn usage(msg: &str) -> ExitCode {
    eprintln!("robodr-executor: {msg}\n{USAGE}");
    ExitCode::from(2)
}

struct Args {
    cmd: String,
    config: Option<PathBuf>,
    out: Option<PathBuf>,
    reason: Option<String>,
    check: bool,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        cmd: "run".into(),
        config: None,
        out: None,
        reason: None,
        check: false,
    };
    let mut it = argv.iter().peekable();
    if let Some(first) = it.peek() {
        if matches!(first.as_str(), "status" | "revert-all" | "keygen") {
            a.cmd = (*first).clone();
            it.next();
        }
    }
    while let Some(x) = it.next() {
        match x.as_str() {
            "--config" => a.config = Some(it.next().ok_or("--config needs a file")?.into()),
            "--out" => a.out = Some(it.next().ok_or("--out needs a file")?.into()),
            "--reason" => a.reason = Some(it.next().ok_or("--reason needs text")?.clone()),
            "--check-config" => a.check = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(a)
}

fn load(path: &std::path::Path) -> Result<(Resolved, robodr_responder::ResponsePolicy), String> {
    let text = config::read_small(path)?;
    let cfg = ExecutorConfig::parse(&text)?.validate()?;
    let policy = config::load_policy(&cfg.config.policy_path)?;
    Ok((cfg, policy))
}

/// Minimal `sd_notify` (std only; no-op without `NOTIFY_SOCKET`).
struct Notify(
    Option<(
        std::os::unix::net::UnixDatagram,
        std::os::unix::net::SocketAddr,
    )>,
);

impl Notify {
    fn from_env() -> Self {
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let Ok(v) = std::env::var("NOTIFY_SOCKET") else {
            return Notify(None);
        };
        let addr = if let Some(name) = v.strip_prefix('@') {
            use std::os::linux::net::SocketAddrExt;
            SocketAddr::from_abstract_name(name.as_bytes()).ok()
        } else if v.starts_with('/') {
            SocketAddr::from_pathname(&v).ok()
        } else {
            None
        };
        Notify(addr.and_then(|a| UnixDatagram::unbound().ok().map(|s| (s, a))))
    }

    fn send(&self, msg: &str) {
        if let Some((s, a)) = &self.0 {
            let _ = s.send_to_addr(msg.as_bytes(), a);
        }
    }
}

fn keygen(out: &PathBuf) -> ExitCode {
    let hex = match Key::generate_hex() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            return ExitCode::from(1);
        }
    };
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out);
    match f.and_then(|mut f| {
        f.write_all(hex.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()
    }) {
        Ok(()) => {
            println!(
                "robodr-executor: wrote a new shared key to {} (0600)",
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "robodr-executor: {}: {e} (an existing key is never overwritten)",
                out.display()
            );
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--version") {
        println!("robodr-executor {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let a = match parse(&argv) {
        Ok(a) => a,
        Err(e) => return usage(&e),
    };
    if a.cmd == "keygen" {
        return match &a.out {
            Some(o) => keygen(o),
            None => usage("keygen needs --out FILE"),
        };
    }
    let Some(cfg_path) = &a.config else {
        return usage("--config is required");
    };
    let (cfg, policy) = match load(cfg_path) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            return ExitCode::from(2);
        }
    };
    if a.cmd == "status" {
        let j = robodr_executor::journal::Journal::new(&cfg.config.state_dir);
        return match j.load() {
            robodr_executor::journal::Loaded::State(s) => {
                println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default());
                ExitCode::SUCCESS
            }
            robodr_executor::journal::Loaded::Fresh => {
                println!("no journal: no action has been executed");
                ExitCode::SUCCESS
            }
            robodr_executor::journal::Loaded::Corrupt(e) => {
                eprintln!("robodr-executor: {e}");
                ExitCode::from(1)
            }
        };
    }
    let key = match Key::load(&cfg.config.key_file) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            return ExitCode::from(2);
        }
    };
    if a.check {
        println!(
            "robodr-executor: configuration ok (robot {}, morphology {}, policy {}validated, \
             {} management / {} uplink / {} control-bus entries, {} motion-path entries)",
            cfg.config.robot_id,
            policy.morphology.as_str(),
            if policy.oem_validated { "" } else { "NOT " },
            cfg.config.network.management.len(),
            cfg.config.network.uplink.len(),
            cfg.config.network.control_buses.entries.len(),
            cfg.config.network.motion_control_path.len()
        );
        return ExitCode::SUCCESS;
    }
    let boot = robodr_executor::boot_id();
    let nft = Box::new(NftCommand::new(&cfg.config.nft));
    let socket = cfg.config.socket.clone();
    let mode = cfg.socket_mode;
    let mut engine = match Engine::open(cfg, policy, nft, &boot, proto::wall_ms()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("robodr-executor: start: {e}");
            return ExitCode::from(1);
        }
    };
    for ev in engine
        .events_since(0, usize::MAX)
        .iter()
        .rev()
        .take(3)
        .rev()
    {
        eprintln!("robodr-executor: {:?}: {}", ev.kind, ev.detail);
    }
    if a.cmd == "revert-all" {
        let reason = format!(
            "operator revert-all: {}",
            a.reason.as_deref().unwrap_or("no reason given")
        );
        return match engine.revert_all(&reason, proto::wall_ms()) {
            Ok(n) => {
                println!("robodr-executor: {n} action(s) reverted; table inet robodr removed");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("robodr-executor: revert-all: {e}");
                ExitCode::from(1)
            }
        };
    }
    let listener = match server::bind(&socket, mode) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            return ExitCode::from(1);
        }
    };
    let notify = Notify::from_env();
    notify.send("READY=1");
    eprintln!(
        "robodr-executor: listening on {} ({} active action(s))",
        socket.display(),
        engine.state().entries.len()
    );
    let mut last_seq = engine.state().next_seq.saturating_sub(1);
    let stats = server::serve(
        &listener,
        &mut engine,
        &key,
        &boot,
        &|| false,
        &mut |e, st| {
            for ev in e.events_since(last_seq, 64) {
                last_seq = ev.seq;
                eprintln!(
                    "robodr-executor: {:?} {} {}",
                    ev.kind,
                    ev.id.as_deref().unwrap_or("-"),
                    ev.detail
                );
            }
            notify.send("WATCHDOG=1");
            notify.send(&format!(
                "STATUS={} active, {} connections, {} rejected",
                e.state().entries.len(),
                st.connections,
                st.rejected
            ));
        },
    );
    eprintln!("robodr-executor: stopped ({stats:?})");
    ExitCode::SUCCESS
}
