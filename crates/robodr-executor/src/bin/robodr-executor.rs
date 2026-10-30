//! `robodr-executor`: the executor process (see the crate docs).
//!
//! ```text
//! robodr-executor --config /etc/robodr/executor.json            run (systemd unit)
//! robodr-executor --config /etc/robodr/executor.json --check-config
//! robodr-executor status --config /etc/robodr/executor.json     print the journal (read-only)
//! robodr-executor revert-all --config /etc/robodr/executor.json [--reason TEXT]
//! robodr-executor rearm --config /etc/robodr/executor.json [--reason TEXT]
//! robodr-executor stop-cleanup --config /etc/robodr/executor.json   (systemd ExecStopPost=)
//! robodr-executor keygen --out /etc/robodr/keys/executor.key
//! robodr-executor seal-journal --config /etc/robodr/executor.json   once, executor stopped
//! ```
//!
//! The journal and the SOC replay store are sealed (HMAC) under a key
//! derived from the link key (`key_file`). `seal-journal` is the one-time
//! upgrade of an executor v1 journal; a v1 journal that was not upgraded is
//! not trusted at start (table deleted, `journal_reset`, orders refused
//! until `rearm`).
//!
//! Exit 0 clean stop, 1 runtime failure, 2 usage / configuration error.
//! The process holds no state outside its journal: a stop or crash at any
//! point is recovered by the reconciliation at the next start, so it has no
//! signal handler (SIGTERM ends it like a crash would, safely).
//!
//! A start that fails for any reason (configuration, key, journal write,
//! socket) deletes table `inet robodr` before it exits: no rule is left
//! without the process that enforces its TTL. `stop-cleanup` does the same
//! after any run that did not end in success (systemd sets
//! `$SERVICE_RESULT`), so a unit that gives up (`StartLimitBurst=`) leaves
//! nothing behind.
//!
//! `rearm` ends an operator's emergency disable (`nft delete table inet
//! robodr`, after which every order is refused) and acknowledges a journal
//! reset. It works on the journal only, as root on the host, while the
//! executor is **stopped** (`systemctl stop robodr-executor` first): the
//! socket agentd uses has no re-arm (review finding 2: agentd holds its
//! key, and must not be able to lift the operator's fence).

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// executor (systemd restarts it and its ExecStopPost removes the table;
// docs/OPERATIONS.md, "Crashes and restarts"). Non-test code has no
// unwrap / expect / panic!-family call and no unchecked indexing;
// arithmetic is left to review.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use robodr_executor::config::{self, ExecutorConfig, Resolved};
use robodr_executor::engine::{self, Engine, Now};
use robodr_executor::nft::NftCommand;
use robodr_executor::proto::{self, Key};
use robodr_executor::server;

const USAGE: &str = "usage: robodr-executor --config FILE [--check-config]\n       \
                     robodr-executor status --config FILE\n       \
                     robodr-executor revert-all --config FILE [--reason TEXT]\n       \
                     robodr-executor rearm --config FILE [--reason TEXT]\n       \
                     robodr-executor stop-cleanup --config FILE\n       \
                     robodr-executor keygen --out FILE\n       \
                     robodr-executor seal-journal --config FILE\n       \
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
        if matches!(
            first.as_str(),
            "status" | "revert-all" | "keygen" | "rearm" | "stop-cleanup" | "seal-journal"
        ) {
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
    if a.cmd == "stop-cleanup" {
        return stop_cleanup(cfg_path);
    }
    let serving = a.cmd == "run" && !a.check;
    let (cfg, policy) = match load(cfg_path) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            if serving {
                fatal_start(None, &e);
            }
            return ExitCode::from(2);
        }
    };
    if a.cmd == "rearm" {
        return rearm(cfg, policy, a.reason.as_deref());
    }
    if a.cmd == "seal-journal" {
        // Gap 1: the one-time upgrade of an executor v1 journal (executor
        // stopped): after it, the journal is sealed under the link key.
        let j = match sealed_journal(&cfg) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("robodr-executor: {e}");
                return ExitCode::from(2);
            }
        };
        return match j.seal_legacy() {
            Ok(m) => {
                println!("robodr-executor: {m}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("robodr-executor: seal-journal: {e}");
                ExitCode::from(1)
            }
        };
    }
    if a.cmd == "status" {
        let j = match sealed_journal(&cfg) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("robodr-executor: {e}");
                return ExitCode::from(2);
            }
        };
        return match j.load() {
            robodr_executor::journal::Loaded::State(s) => {
                if s.operator_disabled {
                    eprintln!(
                        "robodr-executor: DISABLED by the operator (table removed): every order \
                         is refused until `robodr-executor rearm`"
                    );
                }
                if let Some(t) = s.journal_reset_ms {
                    eprintln!(
                        "robodr-executor: HIGH: the journal was unreadable and reset at {t} (Unix \
                         ms): whatever was in force was removed; acknowledge with `rearm`"
                    );
                }
                println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default());
                ExitCode::SUCCESS
            }
            robodr_executor::journal::Loaded::Fresh => {
                println!("no journal: no action has been executed");
                ExitCode::SUCCESS
            }
            robodr_executor::journal::Loaded::Corrupt(e)
            | robodr_executor::journal::Loaded::Untrusted(e) => {
                eprintln!("robodr-executor: {e}");
                ExitCode::from(1)
            }
        };
    }
    let key = match Key::load(&cfg.config.key_file) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            if serving {
                fatal_start(Some(&cfg), &e);
            }
            return ExitCode::from(2);
        }
    };
    // Trust boundary M1: the SOC keys the executor verifies approvals with
    // (re-read before every order; a start never fails on them, reverts and
    // TTL expiry must keep working).
    let soc_keys = robodr_executor::soc::load_keys_checked(
        &cfg.config.soc.keys,
        &cfg.config.soc.robot_keys,
        &cfg.config.robot_id,
    );
    match &soc_keys {
        Err(e) => {
            eprintln!(
                "robodr-executor: soc.keys: {e}: every control-plane order is refused \
                 (soc_keys_unavailable)"
            );
            if a.check {
                return ExitCode::from(2);
            }
        }
        Ok(k) if k.is_empty() => eprintln!(
            "robodr-executor: soc.keys is empty: no SOC approval can be verified, every \
             control-plane order is refused (soc_signature_invalid)"
        ),
        Ok(_) => {}
    }
    if a.check {
        println!(
            "robodr-executor: {} SOC key(s) for approvals",
            soc_keys.map(|k| k.len()).unwrap_or(0)
        );
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
    let cleanup_cfg = cfg.clone();
    let seal = match key.state_seal_key() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("robodr-executor: {e}");
            if serving {
                fatal_start(Some(&cleanup_cfg), &e);
            }
            return ExitCode::from(2);
        }
    };
    let mut engine = match Engine::open_sealed(cfg, policy, nft, &boot, Now::system(), seal) {
        // Policy and configuration are re-read before every order.
        Ok(e) if a.cmd == "run" => e.with_reload(cfg_path.clone()),
        Ok(e) => e,
        Err(e) => {
            // Engine::open deleted the table already.
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
        return match engine.revert_all(&reason, Now::system()) {
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
            let why = format!("executor start failed ({e}): every action reverted");
            if let Err(d) = engine.revert_all(&why, Now::system()) {
                eprintln!("robodr-executor: revert-all after a failed start: {d}");
                fatal_start(Some(&cleanup_cfg), &e);
            }
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
            let st_ = e.state();
            notify.send(&format!(
                "STATUS={} active, {} connections, {} rejected{}{}",
                st_.entries.len(),
                st.connections,
                st.rejected,
                if st_.operator_disabled {
                    ", DISABLED by operator (rearm)"
                } else {
                    ""
                },
                if st_.journal_reset_ms.is_some() {
                    ", HIGH: journal reset"
                } else {
                    ""
                }
            ));
        },
    );
    eprintln!("robodr-executor: stopped ({stats:?})");
    ExitCode::SUCCESS
}

/// A fatal start error: delete the table (and mark the journal when the
/// configuration is known) so no rule outlives TTL enforcement.
fn fatal_start(cfg: Option<&Resolved>, why: &str) {
    let nft_path = cfg
        .map(|c| c.config.nft.clone())
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/nft"));
    let mut nft = NftCommand::new(&nft_path);
    let why = format!(
        "executor start failed ({}): table inet robodr deleted, every action reverted",
        why.chars().take(200).collect::<String>()
    );
    match engine::abandon(cfg, &mut nft, &why, proto::wall_ms()) {
        Ok(n) => eprintln!("robodr-executor: {why} ({n} journalled)"),
        Err(e) => eprintln!("robodr-executor: deleting table inet robodr failed: {e}"),
    }
}

/// `ExecStopPost=`: after a run that did not succeed (systemd's
/// `$SERVICE_RESULT`), delete the table and mark the journal: the unit may
/// not come back (start limit), and nothing would lift the rules at their
/// TTL.
fn stop_cleanup(cfg_path: &std::path::Path) -> ExitCode {
    let result = std::env::var("SERVICE_RESULT").unwrap_or_default();
    if result == "success" {
        return ExitCode::SUCCESS;
    }
    let cfg = config::read_small(cfg_path)
        .and_then(|t| ExecutorConfig::parse(&t))
        .and_then(ExecutorConfig::validate)
        .ok();
    let nft_path = cfg
        .as_ref()
        .map(|c| c.config.nft.clone())
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/nft"));
    let mut nft = NftCommand::new(&nft_path);
    let why = format!(
        "the executor stopped without success ({}): table inet robodr deleted, every action \
         reverted (nothing would enforce its TTL)",
        if result.is_empty() {
            "SERVICE_RESULT unset".to_string()
        } else {
            result
                .chars()
                .filter(char::is_ascii_graphic)
                .take(40)
                .collect()
        }
    );
    match engine::abandon(cfg.as_ref(), &mut nft, &why, proto::wall_ms()) {
        Ok(n) => {
            eprintln!("robodr-executor: {why} ({n} action(s))");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("robodr-executor: stop-cleanup: deleting table inet robodr failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// The journal sealed under the key derived from the link key (gap 1).
fn sealed_journal(cfg: &Resolved) -> Result<robodr_executor::journal::Journal, String> {
    let key = Key::load(&cfg.config.key_file)?;
    Ok(robodr_executor::journal::Journal::sealed(
        &cfg.config.state_dir,
        key.state_seal_key()?,
    ))
}

/// `rearm`: on the journal, only while no executor serves the socket
/// (review finding 2: the protocol socket, whose key agentd holds, has no
/// re-arm).
fn rearm(
    cfg: Resolved,
    policy: robodr_responder::ResponsePolicy,
    reason: Option<&str>,
) -> ExitCode {
    let reason = reason.unwrap_or("no reason given");
    // The journal is sealed under a key derived from the link key (gap 1):
    // without it neither the socket nor the journal can be used.
    let key = match Key::load(&cfg.config.key_file) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("robodr-executor: rearm: {e}");
            return ExitCode::from(2);
        }
    };
    let seal = match key.state_seal_key() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("robodr-executor: rearm: {e}");
            return ExitCode::from(2);
        }
    };
    match server::serving(&cfg.config.socket) {
        Ok(false) => {}
        Ok(true) => {
            eprintln!(
                "robodr-executor: rearm: the executor is running ({}): stop it first \
                 (systemctl stop robodr-executor), re-arm, then start it",
                cfg.config.socket.display()
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!(
                "robodr-executor: rearm: cannot tell whether the executor runs ({e}): run as \
                 root with the executor stopped"
            );
            return ExitCode::from(1);
        }
    }
    let boot = robodr_executor::boot_id();
    let nft = Box::new(NftCommand::new(&cfg.config.nft));
    let mut engine = match Engine::open_sealed(cfg, policy, nft, &boot, Now::system(), seal) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("robodr-executor: rearm: {e}");
            return ExitCode::from(1);
        }
    };
    match engine.rearm(reason, Now::system()) {
        Ok(was) => {
            println!(
                "robodr-executor: re-armed on the journal{}",
                if was { "" } else { " (it was not disabled)" }
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("robodr-executor: rearm: {e}");
            ExitCode::from(1)
        }
    }
}
