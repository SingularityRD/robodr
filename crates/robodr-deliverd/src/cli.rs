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
  robodr-deliverd reanchor     --config FILE --trust TRUST.json [--key FILE]
  robodr-deliverd rekey        --config FILE --old-key FILE --new-key FILE
  robodr-deliverd status       --config FILE
  robodr-deliverd confirm      --config FILE --deployment DIGEST --package NAME
  robodr-deliverd erase        --config FILE --trigger TRIGGER [--device DEV] [--key FILE]
  robodr-deliverd pull         --config FILE
  robodr-deliverd report       --config FILE [--out FILE]
  robodr-deliverd lease        --config FILE --lease FILE
  robodr-deliverd tamper       --socket PATH [--trigger tamper|attestation_failed|auth_failures]
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
              and the lock is lifted. Stop the service first. The
              configured blackbox.key is usually a systemd credential
              that exists only while the service runs: pass the key file
              itself with --key (/etc/robodr/keys/agentd-blackbox.key;
              a regular file of the invoking user, no group or other
              permissions).
rekey         after the unit's black-box key was rotated (OPERATIONS
              §4.3): verify the delivery journal and the high-water
              record with the old key, archive the journal next to it
              (<blackbox.dir>.archived-g<N>) and start a new one, and a
              new record, signed with the new key, carrying the floors,
              the deployment sequence, the chain heads and the time
              floor. Stop the service first; both key files as for
              --key. Never delete the black-box directory instead.
status        print the state (installed versions, floors, deployment).
confirm       record a local operator's confirmation for an RPK that
              requires one (install.requires_operator_present).
erase         crypto-erase the unit's sealing keys (docs/SECURE-DELIVERY.md
              §7.6; needs the seal section): the TPM's erase epoch moves
              on, so every key sealed to the unit is dead; without a TPM
              the runtime volume's LUKS2 keyslots are wiped (seal.device or
              --device, required). With a TPM, a device wipes them too.
              Then seal.stop_units are stopped, runtime_root unmounted and
              seal.mapper_name closed (or suspended when busy). The report
              and robot.seal.erased say what was destroyed and what was
              not. Final: recovery is re-enrolment and re-delivery. TRIGGER is [a-z0-9_]{1,64} (operator, tamper,
              attestation, lease, auth_failures, remote); tamper also
              reports robot.seal.tamper. --key as for reanchor.
pull          fetch this unit's pack from the depot over mutual TLS (the
              depot section; the client key is the TPM-held identity key)
              into media_dir/depot-lan (Sprint 14a). run does this every
              loop when the depot section is set.
report        send this unit's signed install report to the depot (or
              write it to --out for media); a lease in the answer is
              installed (Sprint 14b).
lease         install a site lease file (verified against the enrolled
              lease key).
tamper        the platform feeder's side of the erase trigger socket
              (erase.trigger_socket): sends one trigger line. The agent
              plans the erase with the responder and runs it when the
              live safety state allows (never while moving; Sprint 14b).

Exit codes: 0 ok, 1 refused or error, 2 usage, 3 (run only) the agent's
own executable was replaced (a self-upgrade): the pass in progress was
finished, start it again (the unit does: RestartForceExitStatus=3).";

/// `run` stopped after its pass because its own executable was replaced on
/// disk (T52: RoboDR's package upgraded by this agent; the postinst leaves
/// the restart to it). The unit restarts it on that code.
pub const EXIT_RESTART: i32 = 3;

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
        "init-anchor" => &["config", "trust"],
        "reanchor" => &["config", "trust", "key"],
        "rekey" => &["config", "old-key", "new-key"],
        "confirm" => &["config", "deployment", "package"],
        "erase" => &["config", "trigger", "device", "key"],
        "run" | "once" | "check-config" | "status" | "pull" => &["config"],
        "report" => &["config", "out"],
        "lease" => &["config", "lease"],
        "tamper" => &["socket", "trigger"],
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
    if cmd == "tamper" {
        let r = (|| -> Result<(), String> {
            let t = a.one("trigger")?.unwrap_or("tamper");
            let t = robodr_responder::erase::EraseTrigger::parse(t)
                .filter(|t| t.is_platform_input())
                .ok_or("--trigger tamper|attestation_failed|auth_failures")?;
            crate::erasex::send(Path::new(a.req("socket")?), t)
        })();
        return match r {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("robodr-deliverd: {e}");
                1
            }
        };
    }
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
        "rekey" => rekey(&cfg, &a),
        "status" => status(&cfg),
        "confirm" => confirm(&cfg, &a),
        "erase" => erase(cfg, &a),
        "once" => once(cfg),
        "pull" => crate::lan::pull(&cfg).map(|p| print(serde_json::json!({"pack": p}))),
        "report" => report_cmd(cfg, &a),
        "lease" => lease_cmd(cfg, &a),
        _ => match run_loop(cfg) {
            Ok(Stop::Replaced) => {
                eprintln!(
                    "robodr-deliverd: this program was replaced on disk (an upgrade); \
                     exiting {EXIT_RESTART} to be started again on the new one"
                );
                return EXIT_RESTART;
            }
            Ok(Stop::Signal) => Ok(()),
            Err(e) => Err(e),
        },
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

fn reanchor(mut cfg: Config, a: &Args) -> Result<(), String> {
    let trust = a.req("trust")?.to_string();
    // Review L-B: the black-box key file itself, for a stopped service
    // whose configured key is a systemd credential.
    if let Some(k) = a.one("key")? {
        let p = Path::new(k);
        check_key_file(p)?;
        cfg.blackbox.key = p.to_path_buf();
    }
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let v = e.reanchor(Path::new(&trust)).map_err(|e| e.0);
    let closed = e.close().map_err(|e| e.0);
    print(v?);
    closed
}

fn erase(mut cfg: Config, a: &Args) -> Result<(), String> {
    let trigger = a.req("trigger")?.to_string();
    let device = a.one("device")?.map(std::path::PathBuf::from);
    if let Some(k) = a.one("key")? {
        let p = Path::new(k);
        check_key_file(p)?;
        cfg.blackbox.key = p.to_path_buf();
    }
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let v = e.erase(&trigger, device.as_deref()).map_err(|e| e.0);
    let closed = e.close().map_err(|e| e.0);
    print(v?);
    closed
}

fn report_cmd(cfg: Config, a: &Args) -> Result<(), String> {
    let out = a.one("out")?.map(std::path::PathBuf::from);
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let r = match &out {
        Some(p) => e
            .unit_report()
            .map_err(|e| e.0)
            .and_then(|b| std::fs::write(p, b).map_err(|x| x.to_string()))
            .map(|()| serde_json::json!({"report": p})),
        None => crate::lan::report(&mut e).map(|l| serde_json::json!({"sent": true, "lease": l})),
    };
    let closed = e.close().map_err(|e| e.0);
    print(r?);
    closed
}

fn lease_cmd(cfg: Config, a: &Args) -> Result<(), String> {
    let p = Path::new(a.req("lease")?);
    let b = robodr_release::fsio::read_capped(p, robodr_seal::lease::MAX_LEASE_BYTES)
        .map_err(|e| e.to_string())?;
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let r = e.install_lease(&b).map_err(|e| e.0);
    let closed = e.close().map_err(|e| e.0);
    r?;
    print(serde_json::json!({"lease": "installed"}));
    closed
}

fn rekey(cfg: &Config, a: &Args) -> Result<(), String> {
    let old = Path::new(a.req("old-key")?);
    let new = Path::new(a.req("new-key")?);
    check_key_file(old).map_err(|e| format!("--old-{}", e.trim_start_matches("--")))?;
    check_key_file(new).map_err(|e| format!("--new-{}", e.trim_start_matches("--")))?;
    print(crate::rekey::rekey(cfg, old, new)?);
    Ok(())
}

/// `--key`: an absolute path to a regular file (not a symlink) owned by
/// the invoking user with no group or other permission bits.
fn check_key_file(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !p.is_absolute() {
        return Err(format!("--key {}: not an absolute path", p.display()));
    }
    let md = std::fs::symlink_metadata(p).map_err(|e| format!("--key {}: {e}", p.display()))?;
    let me = crate::users::effective_uid().ok_or("cannot read the effective uid")?;
    if !md.file_type().is_file() || md.uid() != me || md.mode() & 0o077 != 0 {
        return Err(format!(
            "--key {}: must be a regular file owned by uid {me} with no group or other \
             permissions",
            p.display()
        ));
    }
    Ok(())
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

/// Why `run` stopped (without an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// SIGTERM / SIGINT.
    Signal,
    /// The agent's own executable was replaced ([`OwnBinary`]).
    Replaced,
}

/// The executable this process was started from, as path, device and
/// inode taken at start (T52). dpkg replaces a file by renaming a new one
/// over it, so after an upgrade the path names another inode (or nothing)
/// while this process still runs the old one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnBinary {
    path: std::path::PathBuf,
    dev: u64,
    ino: u64,
}

impl OwnBinary {
    /// Of this process (`/proc/self/exe`). `None`: not knowable (already
    /// replaced before the start, or no `/proc`): never reports a change.
    pub fn of_self() -> Option<Self> {
        Self::of(Path::new("/proc/self/exe"))
    }

    /// Of the executable `link` resolves to (`/proc/<pid>/exe`, or any
    /// path in tests).
    pub fn of(link: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let path = std::fs::canonicalize(link).ok()?;
        // The kernel marks an unlinked executable " (deleted)".
        if path.to_string_lossy().ends_with(" (deleted)") {
            return None;
        }
        let m = std::fs::metadata(link).ok()?;
        let p = std::fs::metadata(&path).ok()?;
        if (m.dev(), m.ino()) != (p.dev(), p.ino()) {
            return None;
        }
        Some(Self {
            path,
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    /// The path now names another file, or none.
    pub fn replaced(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&self.path) {
            Ok(m) => (m.dev(), m.ino()) != (self.dev, self.ino),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }
}

fn run_loop(cfg: Config) -> Result<Stop, String> {
    let own = OwnBinary::of_self();
    robodr_agentd::signal::install().map_err(|e| format!("signal handler: {e}"))?;
    let interval = Duration::from_millis(cfg.interval_ms);
    let triggers = match &cfg.erase {
        Some(ec) => Some(crate::erasex::TriggerSocket::bind(ec)?),
        None => None,
    };
    let lan = cfg.depot.is_some();
    let mut last_report: Option<Instant> = None;
    let mut last_pull: Option<Instant> = None;
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    let notifier = robodr_agentd::notify::Notifier::from_env();
    notifier.notify("READY=1");
    let mut res = Ok(Stop::Signal);
    while !robodr_agentd::signal::requested() {
        // Sprint 14b: erase triggers first (planned by the responder,
        // executed when the safety state allows).
        if let Some(t) = &triggers {
            for ev in t.poll() {
                match ev {
                    crate::erasex::Event::Trigger { trigger, uid } => {
                        match e.erase_trigger(trigger, 0) {
                            Ok(what) => println!(
                                "{}",
                                serde_json::json!({"erase_trigger": trigger.as_str(), "uid": uid, "result": what})
                            ),
                            Err(err) => eprintln!("robodr-deliverd: erase: {err}"),
                        }
                    }
                    crate::erasex::Event::Refused { uid, why } => {
                        eprintln!("robodr-deliverd: erase trigger refused (uid {uid:?}): {why}");
                        e.note_refused_trigger(uid, &why);
                    }
                }
            }
        }
        // Sprint 14a: LAN delivery, at most once a minute (failures are
        // retried then; an unchanged pack is not downloaded again).
        if lan && last_pull.is_none_or(|t: Instant| t.elapsed() >= Duration::from_secs(60)) {
            last_pull = Some(Instant::now());
            if let Err(err) = crate::lan::pull_if_changed(e.config()) {
                eprintln!("robodr-deliverd: pull: {err}");
            }
        }
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
                // Reports after any change and at least every minute (the
                // depot's soak needs fresh reports).
                if lan
                    && (busy || last_report.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)))
                {
                    last_report = Some(Instant::now());
                    if let Err(err) = crate::lan::report(&mut e) {
                        eprintln!("robodr-deliverd: report: {err}");
                    }
                }
            }
            Err(err) => {
                // An evidence or state write failed: stop (systemd restarts
                // the unit; the intent in the state file is resumed).
                res = Err(err.0);
                break;
            }
        }
        // T52: checked between passes only, so a pass that installed
        // RoboDR's own package has finished (health gate, commit or
        // rollback) on the old binary first.
        if own.as_ref().is_some_and(OwnBinary::replaced) {
            res = Ok(Stop::Replaced);
            break;
        }
        let until = Instant::now() + interval;
        while Instant::now() < until && !robodr_agentd::signal::requested() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    notifier.notify("STOPPING=1");
    let closed = e.close().map_err(|e| e.0);
    let stop = res?;
    closed?;
    Ok(stop)
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
