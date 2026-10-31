//! `robodr-enroll`: fleet lifecycle on the robot (enrollment, key rotation,
//! revocation lists, SOC-published profiles, update-ring information).
//! See `man robodr-enroll` and docs/contracts/robodr.fleet-api.md.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`; non-test code has no
// unwrap / expect / panic!-family call (a panic would abort a lifecycle
// step, which the journal resumes at the next run, but never silently).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use robodr_fleet::client::Https;
use robodr_fleet::config::{AgentdFacts, Config, DEFAULT_CONFIG};
use robodr_fleet::state::{self, Ctx};
use robodr_fleet::{enroll, fsx, profile, revocation, ring, rotate};

const USAGE: &str = "\
usage:
  robodr-enroll [enroll] (--token-file FILE | --token -) [--reuse-existing-keys]
  robodr-enroll request  (--token-file FILE | --token -) --out FILE [--reuse-existing-keys]
  robodr-enroll accept   --answer FILE
  robodr-enroll rotate   --role uplink|finding [--finish] [--request-out FILE | --answer FILE]
  robodr-enroll rotate   --role uplink|finding --cancel [--request-out FILE | --answer FILE]
  robodr-enroll rotate   --role uplink|finding --abort
  robodr-enroll revocations [fetch] [--platform P]
  robodr-enroll revocations install --file FILE [--platform P]
  robodr-enroll profile  publish --draft FILE
  robodr-enroll profile  fetch
  robodr-enroll profile  stage --profile FILE [--sig FILE]
  robodr-enroll profile  approve (--approval FILE | --fetch)
  robodr-enroll profile  status
  robodr-enroll ring     [--file FILE]
  robodr-enroll status
common options:
  --config FILE          fleet configuration (default /etc/robodr/fleet.json)
  --soc-url URL          SOC API root (https://host/api; overrides soc.url)
  --ca-bundle PEM        SOC CA certificate(s) (overrides soc.ca_bundle)
  --spki-sha256 HEX      pin the SOC server key (repeatable; overrides soc.spki_sha256)
  --soc-key FILE         SOC fleet public key file (repeatable; overrides soc.keys)
  --approval-key FILE    SOC approval public key file (repeatable; overrides soc.approval_keys)
  --agentd-config FILE   agentd configuration (overrides agentd_config)
the token is never taken from the command line (it would show in /proc, sudo logs and
the shell history): --token-file FILE (owned by root, mode 0600 or stricter; shred it
afterwards) or --token - (read from standard input).
exit: 0 ok, 1 refused or failed verification, 2 usage error, 3 SOC not reachable (retry)";

struct Args {
    cmd: Vec<String>,
    opts: Vec<(String, Option<String>)>,
}

const FLAGS: &[&str] = &[
    "--reuse-existing-keys",
    "--finish",
    "--abort",
    "--cancel",
    "--fetch",
    "--help",
    "-h",
    "--version",
];
const VALUED: &[&str] = &[
    "--token",
    "--token-file",
    "--out",
    "--answer",
    "--role",
    "--request-out",
    "--platform",
    "--file",
    "--draft",
    "--profile",
    "--sig",
    "--approval",
    "--config",
    "--soc-url",
    "--ca-bundle",
    "--spki-sha256",
    "--soc-key",
    "--approval-key",
    "--agentd-config",
];
const REPEATABLE: &[&str] = &["--spki-sha256", "--soc-key", "--approval-key"];

const TOKEN_ARGV: &str = "the enrollment token is not accepted on the command line (it would \
show in /proc/<pid>/cmdline, sudo logs and the shell history): put it in a file only root can \
read (--token-file FILE, then shred it) or pass it on standard input (--token -)";

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        cmd: Vec::new(),
        opts: Vec::new(),
    };
    let mut i = 0;
    while i < argv.len() {
        let s = &argv[i];
        if s.starts_with('-') {
            let (name, inline) = match s.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (s.clone(), None),
            };
            if FLAGS.contains(&name.as_str()) {
                if inline.is_some() {
                    return Err(format!("{name} takes no value"));
                }
                a.opts.push((name, None));
            } else if VALUED.contains(&name.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        argv.get(i)
                            .cloned()
                            .ok_or_else(|| format!("{name} needs a value"))?
                    }
                };
                if name == "--token" && v != "-" {
                    return Err(TOKEN_ARGV.into());
                }
                if !REPEATABLE.contains(&name.as_str()) && a.opts.iter().any(|(n, _)| *n == name) {
                    return Err(format!("{name} given twice"));
                }
                a.opts.push((name, Some(v)));
            } else {
                return Err(format!("unknown option {s}"));
            }
        } else {
            a.cmd.push(s.clone());
        }
        i += 1;
    }
    Ok(a)
}

impl Args {
    fn get(&self, n: &str) -> Option<&str> {
        self.opts
            .iter()
            .find(|(k, _)| k == n)
            .and_then(|(_, v)| v.as_deref())
    }
    fn all(&self, n: &str) -> Vec<String> {
        self.opts
            .iter()
            .filter(|(k, _)| k == n)
            .filter_map(|(_, v)| v.clone())
            .collect()
    }
    fn flag(&self, n: &str) -> bool {
        self.opts.iter().any(|(k, _)| k == n)
    }
    /// Only these options are allowed (besides the common ones).
    fn allow(&self, allowed: &[&str]) -> Result<(), Fail> {
        const COMMON: &[&str] = &[
            "--config",
            "--soc-url",
            "--ca-bundle",
            "--spki-sha256",
            "--soc-key",
            "--approval-key",
            "--agentd-config",
        ];
        for (k, _) in &self.opts {
            if !allowed.contains(&k.as_str()) && !COMMON.contains(&k.as_str()) {
                return Err(Fail::Usage(format!("{k} is not an option of this command")));
            }
        }
        Ok(())
    }
}

enum Fail {
    Usage(String),
    Refused(String),
    Unreachable(String),
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        if s.starts_with("SOC not reached") {
            Fail::Unreachable(s)
        } else {
            Fail::Refused(s)
        }
    }
}

fn read_file(p: &str, max: u64) -> Result<Vec<u8>, Fail> {
    fsx::read_capped(Path::new(p), max).map_err(|e| Fail::Refused(format!("{p}: {e}")))
}

fn write_out(p: &str, bytes: &[u8]) -> Result<(), Fail> {
    // Request files carry no secret (public keys, signatures, a MAC);
    // written atomically, mode 0644 set on the descriptor before the
    // rename, for vetted media.
    fsx::write_atomic_with(Path::new(p), bytes, 0o644, None)
        .map_err(|e| Fail::Refused(format!("{p}: {e}")))
}

fn context(a: &Args) -> Result<Ctx, Fail> {
    let (path, explicit) = match a.get("--config") {
        Some(p) => (PathBuf::from(p), true),
        None => (PathBuf::from(DEFAULT_CONFIG), false),
    };
    let mut cfg = Config::load(&path, explicit).map_err(Fail::Refused)?;
    if let Some(u) = a.get("--soc-url") {
        cfg.soc_url = Some(u.to_string());
    }
    if let Some(c) = a.get("--ca-bundle") {
        cfg.ca_bundle = PathBuf::from(c);
    }
    let pins = a.all("--spki-sha256");
    if !pins.is_empty() {
        cfg.spki_sha256 = pins;
    }
    let keys = a.all("--soc-key");
    if !keys.is_empty() {
        cfg.soc_keys = keys.into_iter().map(PathBuf::from).collect();
    }
    let keys = a.all("--approval-key");
    if !keys.is_empty() {
        cfg.approval_keys = keys.into_iter().map(PathBuf::from).collect();
    }
    if let Some(c) = a.get("--agentd-config") {
        cfg.agentd_config = Some(PathBuf::from(c));
    }
    cfg.validate().map_err(Fail::Usage)?;
    let facts = AgentdFacts::load(cfg.agentd_config.as_deref()).map_err(Fail::Refused)?;
    Ctx::open(cfg, facts, Box::new(state::system_now_ms)).map_err(Fail::Refused)
}

fn transport(ctx: &Ctx) -> Result<Https, Fail> {
    let url = ctx.cfg.soc_url.as_deref().ok_or_else(|| {
        Fail::Usage(
            "no SOC URL (--soc-url or fleet.json soc.url); offline: use request/accept".into(),
        )
    })?;
    Https::with_crls(
        url,
        Some(&ctx.cfg.ca_bundle),
        &ctx.cfg.spki_sha256,
        &ctx.cfg.crl_files,
    )
    .map_err(Fail::Usage)
}

/// The enrollment token: from a root-only file or standard input, never
/// from argv (see `TOKEN_ARGV`).
fn token(a: &Args) -> Result<String, Fail> {
    let bytes = match (a.get("--token"), a.get("--token-file")) {
        (Some("-"), None) => {
            use std::io::Read;
            let mut v = Vec::new();
            std::io::stdin()
                .take(8193)
                .read_to_end(&mut v)
                .map_err(|e| Fail::Refused(format!("standard input: {e}")))?;
            if v.len() > 8192 {
                return Err(Fail::Refused("standard input: token too long".into()));
            }
            v
        }
        (Some(_), None) => return Err(Fail::Usage(TOKEN_ARGV.into())),
        (None, Some(f)) => {
            fsx::check_secret_mode(Path::new(f)).map_err(|e| {
                Fail::Refused(format!(
                    "{e}; the token file is a secret: chown root, chmod 0600"
                ))
            })?;
            read_file(f, 8192)?
        }
        _ => {
            return Err(Fail::Usage(
                "give exactly one of --token-file FILE / --token - (standard input)".into(),
            ))
        }
    };
    String::from_utf8(bytes).map_err(|_| Fail::Refused("the token is not UTF-8".into()))
}

fn shred_hint(a: &Args) {
    if let Some(f) = a.get("--token-file") {
        println!("the token is consumed; destroy the token file: shred -u {f}");
    }
}

fn print_prepared(p: &enroll::Prepared) {
    for (role, origin) in &p.key_origin {
        let k = p.pending.keys.iter().find(|k| k.role == *role);
        if let Some(k) = k {
            println!("key {role}: {} ({origin}), {}", k.key_id, k.fingerprint);
        }
    }
    if p.resumed {
        println!(
            "resuming the pending request {} (sent unchanged)",
            p.pending.request_id
        );
    }
}

fn run(a: &Args) -> Result<(), Fail> {
    let cmd: Vec<&str> = a.cmd.iter().map(String::as_str).collect();
    match cmd.as_slice() {
        [] | ["enroll"] => {
            a.allow(&["--token", "--token-file", "--reuse-existing-keys"])?;
            let ctx = context(a)?;
            let mut t = transport(&ctx)?;
            let p = enroll::prepare(
                &ctx,
                &token(a)?,
                &enroll::EnrollOptions {
                    reuse_existing_keys: a.flag("--reuse-existing-keys"),
                },
            )?;
            print_prepared(&p);
            let e = enroll::submit(&ctx, &mut t)?;
            println!(
                "enrolled: robot {} in workspace {} (site {}), answer signed by {}",
                e.robot_id,
                e.workspace,
                e.site.as_deref().unwrap_or("-"),
                e.soc_key_id
            );
            shred_hint(a);
            Ok(())
        }
        ["request"] => {
            a.allow(&["--token", "--token-file", "--out", "--reuse-existing-keys"])?;
            let out = a
                .get("--out")
                .ok_or_else(|| Fail::Usage("request needs --out FILE".into()))?;
            let ctx = context(a)?;
            let p = enroll::prepare(
                &ctx,
                &token(a)?,
                &enroll::EnrollOptions {
                    reuse_existing_keys: a.flag("--reuse-existing-keys"),
                },
            )?;
            print_prepared(&p);
            write_out(out, p.pending.envelope.as_bytes())?;
            println!(
                "enrollment request {} written to {out}; carry it to the SOC, then run \
                 robodr-enroll accept --answer FILE",
                p.pending.request_id
            );
            shred_hint(a);
            Ok(())
        }
        ["accept"] => {
            a.allow(&["--answer"])?;
            let f = a
                .get("--answer")
                .ok_or_else(|| Fail::Usage("accept needs --answer FILE".into()))?;
            let ctx = context(a)?;
            let e = enroll::accept(&ctx, &read_file(f, 64 * 1024)?)?;
            println!(
                "enrolled: robot {} in workspace {}",
                e.robot_id, e.workspace
            );
            Ok(())
        }
        ["rotate"] => cmd_rotate(a),
        ["revocations"] | ["revocations", "fetch"] => {
            a.allow(&["--platform"])?;
            let ctx = context(a)?;
            let platform = match a.get("--platform") {
                Some(p) => p.to_string(),
                None => revocation::platform(&ctx)?,
            };
            let mut t = transport(&ctx)?;
            report_revocations(&revocation::fetch(&ctx, &mut t, &platform)?);
            Ok(())
        }
        ["revocations", "install"] => {
            a.allow(&["--platform", "--file"])?;
            let f = a
                .get("--file")
                .ok_or_else(|| Fail::Usage("revocations install needs --file".into()))?;
            let ctx = context(a)?;
            let platform = match a.get("--platform") {
                Some(p) => p.to_string(),
                None => revocation::platform(&ctx)?,
            };
            report_revocations(&revocation::install(
                &ctx,
                &read_file(f, 1 << 20)?,
                &platform,
            )?);
            Ok(())
        }
        ["profile", sub] => cmd_profile(a, sub),
        ["ring"] => {
            a.allow(&["--file"])?;
            let ctx = context(a)?;
            let s = match a.get("--file") {
                Some(f) => ring::accept(&ctx, &read_file(f, 64 * 1024)?)?,
                None => ring::fetch(&ctx, &mut transport(&ctx)?)?,
            };
            println!(
                "ring {} (serial {}): target {}, installed {}{}{}",
                s.info.ring,
                s.info.serial,
                s.info.target_version.as_deref().unwrap_or("-"),
                s.installed_version,
                if s.update_available {
                    "; an update is available: install it locally with install-bundle.sh \
                     (nothing is installed automatically)"
                } else {
                    ""
                },
                if s.stale {
                    "; WARNING: this ring information has expired"
                } else {
                    ""
                }
            );
            Ok(())
        }
        ["status"] => {
            a.allow(&[])?;
            let ctx = context(a)?;
            match ctx.load::<state::Enrollment>("enrollment.json")? {
                Some(e) => {
                    println!(
                        "enrolled: robot {} workspace {} site {}",
                        e.robot_id,
                        e.workspace,
                        e.site.as_deref().unwrap_or("-")
                    );
                    for k in &e.keys {
                        println!("  {} {} {}", k.role, k.key_id, k.fingerprint);
                    }
                }
                None => match ctx.load::<state::PendingEnroll>("enroll-pending.json")? {
                    Some(p) => println!("enrollment pending: request {}", p.request_id),
                    None => println!("not enrolled"),
                },
            }
            for role in robodr_fleet::wire::ROTATABLE {
                if let Some(r) = rotate::current(&ctx, role)? {
                    println!(
                        "rotation {} ({role}): {:?}, {} -> {}",
                        r.rotation_id, r.phase, r.old_key_id, r.new_key_id
                    );
                }
            }
            if let Some(m) = profile::staged(&ctx)? {
                println!(
                    "staged profile: {} version {} (not enforced; needs an approval)",
                    m.digest, m.profile_version
                );
            }
            Ok(())
        }
        _ => Err(Fail::Usage(format!(
            "unknown command {:?}",
            a.cmd.join(" ")
        ))),
    }
}

fn report_revocations(r: &revocation::Installed) {
    if r.unchanged {
        println!(
            "revocation list serial {} already installed ({})",
            r.serial, r.digest
        );
    } else {
        println!(
            "revocation list serial {} installed ({})",
            r.serial, r.digest
        );
    }
    if let Some(why) = &r.active_profile_refused {
        eprintln!(
            "robodr-enroll: WARNING: with this list agentd refuses the active profile at its \
             next start (observe-only): {why}"
        );
    }
}

fn cmd_rotate(a: &Args) -> Result<(), Fail> {
    a.allow(&[
        "--role",
        "--finish",
        "--abort",
        "--cancel",
        "--request-out",
        "--answer",
    ])?;
    let role = a
        .get("--role")
        .ok_or_else(|| Fail::Usage("rotate needs --role uplink|finding".into()))?;
    if !robodr_fleet::wire::ROTATABLE.contains(&role) {
        return Err(Fail::Usage(format!("--role {role:?}: uplink or finding")));
    }
    if a.get("--request-out").is_some() && a.get("--answer").is_some() {
        return Err(Fail::Usage(
            "--request-out and --answer are separate steps".into(),
        ));
    }
    if [a.flag("--finish"), a.flag("--abort"), a.flag("--cancel")]
        .iter()
        .filter(|f| **f)
        .count()
        > 1
    {
        return Err(Fail::Usage(
            "--finish, --cancel and --abort are separate steps".into(),
        ));
    }
    let ctx = context(a)?;
    let service = if role == "uplink" {
        "robodr-uplink"
    } else {
        "robodr-agentd"
    };
    let crash = &rotate::no_crash;
    if a.flag("--abort") {
        rotate::abort(&ctx, role)?;
        println!("rotation of the {role} key aborted; the new key was shredded");
        return Ok(());
    }
    if a.flag("--cancel") {
        if let Some(out) = a.get("--request-out") {
            write_out(out, &rotate::cancel_request(&ctx, role)?)?;
            println!(
                "cancel request written to {out}; carry it to the SOC, then run \
                 robodr-enroll rotate --role {role} --cancel --answer FILE"
            );
            return Ok(());
        }
        match a.get("--answer") {
            Some(f) => rotate::cancelled(&ctx, role, &read_file(f, 64 * 1024)?)?,
            None => rotate::submit_cancel(&ctx, &mut transport(&ctx)?, role)?,
        }
        println!(
            "rotation of the {role} key cancelled at the SOC; the new key was shredded, the \
             old key stays active"
        );
        return Ok(());
    }
    if a.flag("--finish") {
        if let Some(out) = a.get("--request-out") {
            write_out(out, &rotate::retire_request(&ctx, role)?)?;
            println!("retire request written to {out}");
            return Ok(());
        }
        let en = match a.get("--answer") {
            Some(f) => rotate::finish(&ctx, role, &read_file(f, 64 * 1024)?, crash)?,
            None => rotate::submit_retire(&ctx, &mut transport(&ctx)?, role, crash)?,
        };
        let k = en.key(role).map(|k| k.key_id.clone()).unwrap_or_default();
        println!("rotation finished: the old {role} key is retired at the SOC and shredded; active key {k}");
        return Ok(());
    }
    let rot = rotate::prepare(&ctx, role, crash)?;
    if let Some(out) = a.get("--request-out") {
        write_out(out, &rotate::request_out(&ctx, role)?)?;
        println!(
            "rotate request {} written to {out}; carry it to the SOC, then run \
             robodr-enroll rotate --role {role} --answer FILE",
            rot.rotation_id
        );
        return Ok(());
    }
    match a.get("--answer") {
        Some(f) => {
            rotate::register(&ctx, role, &read_file(f, 64 * 1024)?)?;
        }
        None => {
            rotate::submit_rotate(&ctx, &mut transport(&ctx)?, role)?;
        }
    }
    let rot = rotate::swap(&ctx, role, crash)?;
    println!(
        "rotation {}: the SOC accepts both keys (overlap); {} is now the active {role} key.\n\
         Next: systemctl restart {service}; once it runs with the new key{}, run \
         robodr-enroll rotate --role {role} --finish",
        rot.rotation_id,
        rot.new_key_id,
        if role == "finding" {
            " and the findings signed with the old key are delivered"
        } else {
            ""
        }
    );
    Ok(())
}

fn cmd_profile(a: &Args, sub: &str) -> Result<(), Fail> {
    match sub {
        "publish" => {
            a.allow(&["--draft"])?;
            let f = a
                .get("--draft")
                .ok_or_else(|| Fail::Usage("profile publish needs --draft FILE".into()))?;
            let ctx = context(a)?;
            let d = profile::publish_draft(&ctx, &mut transport(&ctx)?, Path::new(f))?;
            println!("draft {d} sent to the SOC for review");
            Ok(())
        }
        "fetch" | "stage" => {
            let ctx;
            let m = if sub == "fetch" {
                a.allow(&[])?;
                ctx = context(a)?;
                profile::fetch(&ctx, &mut transport(&ctx)?)?
            } else {
                a.allow(&["--profile", "--sig"])?;
                let p = a
                    .get("--profile")
                    .ok_or_else(|| Fail::Usage("profile stage needs --profile FILE".into()))?;
                let sig = a
                    .get("--sig")
                    .map_or_else(|| format!("{p}.sig"), str::to_string);
                ctx = context(a)?;
                profile::stage(
                    &ctx,
                    &read_file(p, 8 * 1024 * 1024)?,
                    &read_file(&sig, 64 * 1024)?,
                )?
            };
            println!(
                "profile {} (version {}, platform {}) verified and STAGED; it is not enforced. \
                 Install it with an approval: robodr-enroll profile approve --approval FILE | --fetch",
                m.digest, m.profile_version, m.platform
            );
            Ok(())
        }
        "approve" => {
            a.allow(&["--approval", "--fetch"])?;
            let ctx = context(a)?;
            let bytes = match (a.get("--approval"), a.flag("--fetch")) {
                (Some(f), false) => read_file(f, 64 * 1024)?,
                (None, true) => profile::fetch_approval(&ctx, &mut transport(&ctx)?)?,
                _ => {
                    return Err(Fail::Usage(
                        "give exactly one of --approval FILE / --fetch".into(),
                    ))
                }
            };
            let i = profile::approve(&ctx, &bytes)?;
            println!(
                "profile {} (version {}) installed at {} (approval {} by {}); restart \
                 robodr-agentd to enforce it (agentd verifies it again at start){}",
                i.meta.digest,
                i.meta.profile_version,
                i.path.display(),
                i.approval_id,
                i.approved_by.join(", "),
                i.backup
                    .map(|b| format!("; previous profile kept in {}", b.display()))
                    .unwrap_or_default()
            );
            Ok(())
        }
        "status" => {
            a.allow(&[])?;
            let ctx = context(a)?;
            match profile::staged(&ctx)? {
                Some(m) => println!(
                    "staged: {} version {} platform {} (not enforced)",
                    m.digest, m.profile_version, m.platform
                ),
                None => println!("no staged profile"),
            }
            Ok(())
        }
        other => Err(Fail::Usage(format!("unknown profile command {other:?}"))),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("robodr-enroll: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if a.flag("--help") || a.flag("-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if a.flag("--version") {
        println!(
            "{}",
            robodr_buildinfo::version_line("robodr-enroll", env!("CARGO_PKG_VERSION"))
        );
        return ExitCode::SUCCESS;
    }
    match run(&a) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Usage(e)) => {
            eprintln!("robodr-enroll: {e}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Fail::Refused(e)) => {
            eprintln!("robodr-enroll: {e}");
            ExitCode::from(1)
        }
        Err(Fail::Unreachable(e)) => {
            eprintln!("robodr-enroll: {e}");
            ExitCode::from(3)
        }
    }
}
