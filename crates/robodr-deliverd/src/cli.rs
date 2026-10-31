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
  robodr-deliverd self-check   --config FILE
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
  robodr-deliverd safety-state [--config FILE]
  robodr-deliverd verify-minisign --pubkey FILE --file FILE [--sig FILE]
  robodr-deliverd verify-minisign --self-test
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
self-check    read what `run` needs before it starts (configuration,
              state file, black-box and finding keys) without writing;
              exit 0 if all of it loads. The running agent runs it on a
              new robodr-deliverd that its own deb install put in place,
              and rolls that install back if it fails.
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
              a regular file of the invoking user or root, no group or
              other permissions).
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
safety-state  print the live safety state as the install gate sees it
              (agentd's status socket, peer-checked; the safety section
              of --config, or its defaults) and whether agentd's
              heartbeat is fresh. Exit 0 when an install / restart of
              the gateway and executor may run now (idle or
              safe_state_active), 1 when it must wait. Used by
              install-bundle.sh (package upgrades, OPERATIONS.md 7).
verify-minisign
              check a minisign signature (FILE.minisig, or --sig) of
              FILE against the public key file with RoboDR's built-in
              verifier (prehashed signatures only, as release.yml
              makes them); prints the trusted comment. --self-test runs
              the verifier's known-answer test. Used by
              install-bundle.sh instead of the minisign program.

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
        println!(
            "{}",
            robodr_buildinfo::version_line("robodr-deliverd", env!("CARGO_PKG_VERSION"))
        );
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
        "run" | "once" | "check-config" | "self-check" | "status" | "pull" => &["config"],
        "report" => &["config", "out"],
        "lease" => &["config", "lease"],
        "tamper" => &["socket", "trigger"],
        "safety-state" => &["config"],
        "verify-minisign" => &["pubkey", "file", "sig"],
        other => {
            return usage(
                &format!("unknown command {other:?}"),
                USAGE,
                "robodr-deliverd",
            )
        }
    };
    let switches: &[&str] = if cmd == "verify-minisign" {
        &["self-test"]
    } else {
        &[]
    };
    let a = match parse_args_with_switches(rest, known, switches) {
        Ok(a) => a,
        Err(e) => return usage(&e, USAGE, "robodr-deliverd"),
    };
    if cmd == "verify-minisign" {
        return match verify_minisign(&a) {
            Ok(tc) => {
                println!("{tc}");
                0
            }
            Err(e) => {
                eprintln!("robodr-deliverd: verify-minisign: {e}");
                1
            }
        };
    }
    if cmd == "safety-state" {
        return safety_state(&a);
    }
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
    let cfg_path = match a.req("config") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(e) => return usage(&e, USAGE, "robodr-deliverd"),
    };
    let cfg = match Config::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("robodr-deliverd: configuration: {e}");
            return 2;
        }
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
        "self-check" => self_check(&cfg),
        "once" => once(cfg, &cfg_path),
        "pull" => crate::lan::pull(&cfg).map(|p| print(serde_json::json!({"pack": p}))),
        "report" => report_cmd(cfg, &a),
        "lease" => lease_cmd(cfg, &a),
        _ => match run_loop(cfg, &cfg_path) {
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

/// `verify-minisign`: the trusted comment of a valid signature.
fn verify_minisign(a: &Args) -> Result<String, String> {
    use robodr_pkg::minisign::{self, PublicKey, Signature, MAX_FILE};
    use std::io::Read;
    if a.flag("self-test") {
        if a.one("pubkey")?.is_some() || a.one("file")?.is_some() || a.one("sig")?.is_some() {
            return Err("--self-test takes no other option".into());
        }
        minisign::run_self_test().map_err(|r| r.to_string())?;
        return Ok("self-test ok".into());
    }
    let file = Path::new(a.req("file")?);
    let sig = match a.one("sig")? {
        Some(s) => std::path::PathBuf::from(s),
        None => {
            let mut s = file.as_os_str().to_os_string();
            s.push(".minisig");
            std::path::PathBuf::from(s)
        }
    };
    let read = |p: &Path| robodr_release::fsio::read_capped(p, MAX_FILE).map_err(|e| e.to_string());
    let pk = PublicKey::parse(&read(Path::new(a.req("pubkey")?))?)
        .map_err(|r| format!("public key: {r}"))?;
    let s = Signature::parse(&read(&sig)?).map_err(|r| format!("{}: {r}", sig.display()))?;
    let (mut f, _) = robodr_release::fsio::open_regular(file).map_err(|e| e.to_string())?;
    let mut h = robodr_pkg::blake2b::Blake2b512::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", file.display()))?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    let tc = s
        .verify_digest(&pk, &h.finalize())
        .map_err(|r| format!("{}: {r}", file.display()))?;
    Ok(tc.to_string())
}

/// `safety-state`: exit 0 when the gate is open, 1 when it is not.
fn safety_state(a: &Args) -> i32 {
    let cfg = match a.one("config") {
        Ok(Some(p)) => match Config::load(Path::new(p)) {
            Ok(c) => c.safety,
            Err(e) => {
                eprintln!("robodr-deliverd: configuration: {e}");
                return 2;
            }
        },
        Ok(None) => crate::config::SafetyCfg::default(),
        Err(e) => return usage(&e, USAGE, "robodr-deliverd"),
    };
    let (o, hb) = crate::safety::observe_with_heartbeat(&cfg);
    print(serde_json::json!({
        "safety_state": crate::safety::state_name(o.state),
        "allows_restart": o.allows_install(),
        "why": o.why,
        "agentd_health": o.agentd_health,
        "agentd_fresh": hb.is_ok(),
        "agentd_why": hb.err(),
    }));
    if o.allows_install() {
        0
    } else {
        1
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

/// `--key`: an absolute path to a regular file (not a symlink) that passes
/// the shared secret-file rule (`robodr_blackbox::secret_file`): owned by
/// the invoking user or root with no group or other permission bits, or a
/// systemd credential only root and the invoking user can read.
fn check_key_file(p: &Path) -> Result<(), String> {
    if !p.is_absolute() {
        return Err(format!("--key {}: not an absolute path", p.display()));
    }
    robodr_blackbox::secret_file::check_secret_path(p)
        .map(|_| ())
        .map_err(|e| format!("--key {}: {e}", p.display()))
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

/// `self-check`: what `run` needs before READY, read only
/// ([`Engine::self_check`]). Run by the old agent on a binary that
/// replaced it, before that install commits ([`crate::own::SelfCheck`]).
fn self_check(cfg: &Config) -> Result<(), String> {
    Engine::self_check(cfg).map_err(|e| e.0)?;
    println!("robodr-deliverd: self-check ok");
    Ok(())
}

/// The check of a replaced own binary for an engine started from the
/// configuration file `cfg_path`, or why there can be none.
fn own_self_check(
    own: Option<OwnBinary>,
    cfg_path: &Path,
) -> Result<crate::own::SelfCheck, String> {
    let exe = own.ok_or(
        "the executable of this process is not known (/proc/self/exe did not resolve to a \
         file, or it was replaced or removed before the start)",
    )?;
    let config = std::path::absolute(cfg_path)
        .map_err(|e| format!("configuration path {}: {e}", cfg_path.display()))?;
    Ok(crate::own::SelfCheck::new(exe, config))
}

/// Give the engine the check of a replaced own binary, or note in the
/// journal (and on stderr) that deb installs commit without it.
fn arm_self_check(e: &mut Engine, c: Result<crate::own::SelfCheck, String>) -> Result<(), String> {
    match c {
        Ok(c) => {
            e.set_self_check(Some(c));
            Ok(())
        }
        Err(why) => {
            eprintln!(
                "robodr-deliverd: warning: a self-upgrade will commit without the self-check \
                 of the new binary: {why}"
            );
            e.self_check_unavailable(&why).map_err(|e| e.0)
        }
    }
}

fn once(cfg: Config, cfg_path: &Path) -> Result<(), String> {
    let mut e = Engine::open(cfg, Box::new(SystemClock)).map_err(|e| e.0)?;
    if let Err(err) = arm_self_check(&mut e, own_self_check(OwnBinary::of_self(), cfg_path)) {
        let _ = e.close();
        return Err(err);
    }
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

pub use crate::own::OwnBinary;

fn run_loop(cfg: Config, cfg_path: &Path) -> Result<Stop, String> {
    let own = OwnBinary::of_self();
    let check = own_self_check(own.clone(), cfg_path);
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
    if let Err(err) = arm_self_check(&mut e, check) {
        let _ = e.close();
        return Err(err);
    }
    let mut stayed = false;
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
            // WP14: not into a replacement that failed its self-check and
            // is still in place (its rollback was blocked): this old code
            // keeps running until it is stopped.
            if !e.own_replacement_failed() {
                res = Ok(Stop::Replaced);
                break;
            }
            if !stayed {
                stayed = true;
                eprintln!(
                    "robodr-deliverd: this program was replaced by a binary that failed its \
                     self-check and was not rolled back; staying on the running one (a restart \
                     starts the failing binary)"
                );
            }
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
        println!(
            "{}",
            robodr_buildinfo::version_line("robodr-safety-replay", env!("CARGO_PKG_VERSION"))
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// WP14: an agent that cannot know its own executable says why (the
    /// caller notes it in the journal) instead of dropping the check.
    #[test]
    fn an_unknown_own_executable_is_a_reason_not_a_silent_skip() {
        let why = own_self_check(None, Path::new("/etc/robodr/deliverd.json")).unwrap_err();
        assert!(why.contains("/proc/self/exe"), "{why}");
        let why = own_self_check(OwnBinary::of_self(), Path::new("")).unwrap_err();
        assert!(why.contains("configuration path"), "{why}");
        let c = own_self_check(OwnBinary::of_self(), Path::new("deliverd.json")).unwrap();
        assert!(c.config.is_absolute());
    }
}
