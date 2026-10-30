//! `robodr-depot` command line (see [`USAGE`]).

use crate::config::Config;
use crate::depot::{Depot, RolloutParams};
use crate::{err, DepotError};
use robodr_diode::cli::{argv, is_version_request, parse_args_with_switches, Args};
use serde_json::json;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "\
usage:
  robodr-depot --config FILE init --trust TRUST.json
  robodr-depot --config FILE trust update --trust TRUST.json
  robodr-depot entry scan --bundle DIR --trust TRUST.json --trust-anchor ANCHOR.json
        --root FINGERPRINT [--root ..] --site SITE --station NAME --key ENTRY.key
        --history DIR [--vulndb DB.json] [--fail-on low|medium|high|critical]
        [--lifetime-days N] --out REPORT.json
  robodr-depot --config FILE import --bundle DIR --report REPORT.json
  robodr-depot --config FILE enrol begin --unit U
  robodr-depot --config FILE enrol verify --request REQ.json --out CHALLENGE.json
  robodr-depot --config FILE enrol finish --response RESP.json
  robodr-depot --config FILE enrol approve --unit U --key OPERATOR.key
  robodr-depot --config FILE enrol export --unit U --out DIR
  robodr-depot --config FILE unit revoke --unit U --key OP.key --key OP.key
  robodr-depot --config FILE inventory
  robodr-depot --config FILE rollout create --id ID --rpk DIGEST [--rpk ..] --stages lab,canary,ring-1
        [--batch N] [--soak-s S] [--max-failures F] [--validity-days D] [--unit U]...
  robodr-depot --config FILE rollout advance --id ID
  robodr-depot --config FILE rollout resume --id ID --key OP.key --key OP.key
  robodr-depot --config FILE rollout abort --id ID --key OP.key --key OP.key
  robodr-depot --config FILE deploy approve --seq N --key OPERATOR.key
  robodr-depot --config FILE report import --report REPORT.json
  robodr-depot --config FILE pack --unit U --out DIR
  robodr-depot --config FILE serve
  robodr-depot --config FILE reanchor --min-deployment-seq N --key OP.key --key OP.key
  robodr-depot --version

docs/SECURE-DELIVERY.md §4-§6, §8. A bundle is imported only with a passing
entry report for exactly that bundle (entry scan on the entry station).
Units enrol with TPM credential activation and two operators. A rollout
goes ring by ring; each stage's deployment needs the operator quorum of its
ring (deploy approve), and the next stage exists only after every unit of
the current one reported its items installed and healthy after the soak; a
failing report halts the rollout until operators resume it. Units fetch
their pack over mutual TLS (serve) or receive a per-unit media pack (pack).

Exit codes: 0 ok, 1 refused or error, 2 usage.";

enum Cmd {
    Usage(String),
    Fail(DepotError),
}

impl From<DepotError> for Cmd {
    fn from(e: DepotError) -> Self {
        Cmd::Fail(e)
    }
}

fn usage(msg: &str) -> i32 {
    eprintln!("robodr-depot: {msg}\n\n{USAGE}");
    2
}

fn print(v: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
}

/// Entry point of the binary.
pub fn main_with_env() -> i32 {
    match argv() {
        Ok(a) => run(a),
        Err(e) => usage(&e),
    }
}

/// Run one command line (without the program name).
pub fn run(args: Vec<String>) -> i32 {
    if is_version_request(&args) {
        println!("robodr-depot {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if matches!(args.as_slice(), [a] if a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return usage("--help is only accepted alone");
    }
    let r = dispatch(args);
    match r {
        Ok(()) => 0,
        Err(Cmd::Usage(m)) => usage(&m),
        Err(Cmd::Fail(e)) => {
            eprintln!("robodr-depot: {e}");
            1
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<(), Cmd> {
    let mut it = args.into_iter().peekable();
    let mut config = None;
    if it.peek().map(String::as_str) == Some("--config") {
        it.next();
        config = Some(PathBuf::from(
            it.next()
                .ok_or_else(|| Cmd::Usage("--config needs a file".into()))?,
        ));
    }
    let cmd = it
        .next()
        .ok_or_else(|| Cmd::Usage("missing command".into()))?;
    let rest: Vec<String> = it.collect();
    if cmd == "entry" {
        return entry(rest);
    }
    let cfg = Config::load(&config.ok_or_else(|| Cmd::Usage("--config FILE first".into()))?)?;
    let now = crate::now()?;
    match cmd.as_str() {
        "init" => {
            let a = parse(rest, &["trust"])?;
            Depot::init(&cfg, &path(&a, "trust")?, now)?;
            print(json!({"initialised": cfg.state_dir}));
            Ok(())
        }
        "serve" => {
            parse(rest, &[])?;
            let d = Depot::open(cfg, now)?;
            let listen = d
                .cfg
                .serve
                .as_ref()
                .map(|s| s.listen.clone())
                .ok_or_else(|| err("no serve configuration"))?;
            let l =
                std::net::TcpListener::bind(&listen).map_err(|e| err(format!("{listen}: {e}")))?;
            eprintln!("robodr-depot: serving on {listen}");
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let clock: crate::serve::Clock = std::sync::Arc::new(|| crate::now().unwrap_or(0));
            crate::serve::serve(
                std::sync::Arc::new(std::sync::Mutex::new(d)),
                l,
                stop,
                clock,
            )?;
            Ok(())
        }
        _ => {
            let mut d = Depot::open(cfg, now)?;
            run_cmd(&mut d, &cmd, rest, now)
        }
    }
}

fn parse(args: Vec<String>, known: &[&str]) -> Result<Args, Cmd> {
    parse_args_with_switches(args, known, &[]).map_err(Cmd::Usage)
}

fn req<'a>(a: &'a Args, f: &str) -> Result<&'a str, Cmd> {
    a.req(f).map_err(Cmd::Usage)
}

fn path(a: &Args, f: &str) -> Result<PathBuf, Cmd> {
    Ok(PathBuf::from(req(a, f)?))
}

fn read(p: &Path) -> Result<Vec<u8>, Cmd> {
    robodr_release::fsio::read_capped(p, 64 << 20).map_err(|e| Cmd::Fail(err(e.to_string())))
}

fn signer(p: &str) -> Result<Box<dyn robodr_blackbox::Signer>, Cmd> {
    robodr_blackbox::KeyFile::load_secret(Path::new(p))
        .and_then(|k| k.signer())
        .map_err(|e| Cmd::Fail(err(format!("{p}: {e}"))))
}

fn signers(a: &Args) -> Result<Vec<Box<dyn robodr_blackbox::Signer>>, Cmd> {
    a.all("key").into_iter().map(signer).collect()
}

fn sub2<'a>(rest: &'a [String]) -> Result<(&'a str, Vec<String>), Cmd> {
    let (s, r) = rest
        .split_first()
        .ok_or_else(|| Cmd::Usage("missing subcommand".into()))?;
    Ok((s.as_str(), r.to_vec()))
}

fn run_cmd(d: &mut Depot, cmd: &str, rest: Vec<String>, now: u64) -> Result<(), Cmd> {
    match cmd {
        "trust" => {
            let (s, r) = sub2(&rest)?;
            if s != "update" {
                return Err(Cmd::Usage(format!("unknown subcommand {s:?}")));
            }
            let a = parse(r, &["trust"])?;
            let v = d.update_trust(&path(&a, "trust")?, now)?;
            print(json!({"trust_version": v}));
        }
        "import" => {
            let a = parse(rest, &["bundle", "report"])?;
            let l = d.import(&path(&a, "bundle")?, &path(&a, "report")?, now)?;
            print(json!({"imported": l}));
        }
        "enrol" => {
            let (s, r) = sub2(&rest)?;
            match s {
                "begin" => {
                    let a = parse(r, &["unit"])?;
                    let n = d.enrol_begin(req(&a, "unit")?, now)?;
                    print(json!({"unit": req(&a, "unit")?, "nonce": n}));
                }
                "verify" => {
                    let a = parse(r, &["request", "out"])?;
                    let c = d.enrol_verify(&read(&path(&a, "request")?)?, now)?;
                    match c {
                        Some(c) => {
                            let o = path(&a, "out")?;
                            std::fs::write(&o, c).map_err(|e| err(e.to_string()))?;
                            print(json!({"challenge": o}));
                        }
                        None => {
                            print(json!({"challenge": null, "activated": true, "attested": false}))
                        }
                    }
                }
                "finish" => {
                    let a = parse(r, &["response"])?;
                    let u = d.enrol_finish(&read(&path(&a, "response")?)?, now)?;
                    print(json!({"activated": u}));
                }
                "approve" => {
                    let a = parse(r, &["unit", "key"])?;
                    let k = signer(req(&a, "key")?)?;
                    let done = d.enrol_approve(req(&a, "unit")?, k.as_ref(), now)?;
                    print(json!({"enrolled": done}));
                }
                "export" => {
                    let a = parse(r, &["unit", "out"])?;
                    d.enrol_export(req(&a, "unit")?, &path(&a, "out")?)?;
                    print(json!({"exported": req(&a, "out")?}));
                }
                _ => return Err(Cmd::Usage(format!("unknown subcommand {s:?}"))),
            }
        }
        "unit" => {
            let (s, r) = sub2(&rest)?;
            if s != "revoke" {
                return Err(Cmd::Usage(format!("unknown subcommand {s:?}")));
            }
            let a = parse(r, &["unit", "key"])?;
            let ks = signers(&a)?;
            let refs: Vec<&dyn robodr_blackbox::Signer> = ks.iter().map(|k| k.as_ref()).collect();
            d.revoke(req(&a, "unit")?, &refs)?;
            print(json!({"revoked": req(&a, "unit")?}));
        }
        "inventory" => {
            parse(rest, &[])?;
            print(d.inventory());
        }
        "rollout" => {
            let (s, r) = sub2(&rest)?;
            match s {
                "create" => {
                    let a = parse(
                        r,
                        &[
                            "id",
                            "rpk",
                            "stages",
                            "batch",
                            "soak-s",
                            "max-failures",
                            "validity-days",
                            "unit",
                        ],
                    )?;
                    let mut p = RolloutParams::default();
                    if let Some(v) = a.num::<u32>("batch").map_err(Cmd::Usage)? {
                        p.batch_size = v;
                    }
                    if let Some(v) = a.num::<u32>("soak-s").map_err(Cmd::Usage)? {
                        p.soak_s = v;
                    }
                    if let Some(v) = a.num::<u32>("max-failures").map_err(Cmd::Usage)? {
                        p.max_failures = v;
                    }
                    if let Some(v) = a.num::<u64>("validity-days").map_err(Cmd::Usage)? {
                        p.validity_s = v.saturating_mul(86400);
                    }
                    let only: Vec<String> = a.all("unit").iter().map(|s| s.to_string()).collect();
                    if !only.is_empty() {
                        p.units = Some(only);
                    }
                    let items: Vec<String> = a.all("rpk").iter().map(|s| s.to_string()).collect();
                    let stages: Vec<String> =
                        req(&a, "stages")?.split(',').map(str::to_string).collect();
                    let seq = d.rollout_create(req(&a, "id")?, &items, &stages, &p, now)?;
                    print(json!({"rollout": req(&a, "id")?, "deployment_seq": seq}));
                }
                "advance" => {
                    let a = parse(r, &["id"])?;
                    let s = d.rollout_advance(req(&a, "id")?, now)?;
                    print(json!({"deployment_seq": s, "completed": s.is_none()}));
                }
                "resume" | "abort" => {
                    let a = parse(r, &["id", "key"])?;
                    let ks = signers(&a)?;
                    let refs: Vec<&dyn robodr_blackbox::Signer> =
                        ks.iter().map(|k| k.as_ref()).collect();
                    if s == "resume" {
                        let seq = d.rollout_resume(req(&a, "id")?, &refs, now)?;
                        print(json!({"deployment_seq": seq}));
                    } else {
                        d.rollout_abort(req(&a, "id")?, &refs)?;
                        print(json!({"aborted": req(&a, "id")?}));
                    }
                }
                _ => return Err(Cmd::Usage(format!("unknown subcommand {s:?}"))),
            }
        }
        "deploy" => {
            let (s, r) = sub2(&rest)?;
            if s != "approve" {
                return Err(Cmd::Usage(format!("unknown subcommand {s:?}")));
            }
            let a = parse(r, &["seq", "key"])?;
            let seq = a
                .num::<u64>("seq")
                .map_err(Cmd::Usage)?
                .ok_or_else(|| Cmd::Usage("--seq".into()))?;
            let k = signer(req(&a, "key")?)?;
            let active = d.deploy_approve(seq, k.as_ref(), now)?;
            print(json!({"deployment_seq": seq, "active": active}));
        }
        "report" => {
            let (s, r) = sub2(&rest)?;
            if s != "import" {
                return Err(Cmd::Usage(format!("unknown subcommand {s:?}")));
            }
            let a = parse(r, &["report"])?;
            let l = d.accept_report(None, &read(&path(&a, "report")?)?, now)?;
            print(json!({"accepted": true, "lease": l}));
        }
        "pack" => {
            let a = parse(rest, &["unit", "out"])?;
            let n = d.write_pack(req(&a, "unit")?, &path(&a, "out")?)?;
            print(json!({"files": n}));
        }
        "reanchor" => {
            let a = parse(rest, &["min-deployment-seq", "key"])?;
            let n = a
                .num::<u64>("min-deployment-seq")
                .map_err(Cmd::Usage)?
                .ok_or_else(|| Cmd::Usage("--min-deployment-seq".into()))?;
            let ks = signers(&a)?;
            let refs: Vec<&dyn robodr_blackbox::Signer> = ks.iter().map(|k| k.as_ref()).collect();
            d.reanchor(n, &refs)?;
            print(json!({"reanchored": true, "deployment_seq": d.db.deployment_seq}));
        }
        other => return Err(Cmd::Usage(format!("unknown command {other:?}"))),
    }
    Ok(())
}

fn entry(rest: Vec<String>) -> Result<(), Cmd> {
    let (s, r) = sub2(&rest)?;
    if s != "scan" {
        return Err(Cmd::Usage(format!("unknown subcommand {s:?}")));
    }
    let a = parse(
        r,
        &[
            "bundle",
            "trust",
            "trust-anchor",
            "root",
            "site",
            "station",
            "key",
            "history",
            "vulndb",
            "fail-on",
            "lifetime-days",
            "out",
        ],
    )?;
    let now = crate::now()?;
    let roots: Vec<String> = a.all("root").iter().map(|s| s.to_string()).collect();
    let site = robodr_release::ops::SiteTrust::anchored(
        &path(&a, "trust")?,
        &path(&a, "trust-anchor")?,
        &roots,
        req(&a, "site")?,
        now,
    )
    .map_err(|e| err(e.to_string()))?;
    let fail_on = match a.one("fail-on").map_err(Cmd::Usage)? {
        None => robodr_pkg::entry::Severity::High,
        Some(s) => robodr_pkg::entry::Severity::parse(s)
            .ok_or_else(|| Cmd::Usage("--fail-on low|medium|high|critical".into()))?,
    };
    let days = a
        .num::<u64>("lifetime-days")
        .map_err(Cmd::Usage)?
        .unwrap_or(7);
    let vulndb = a.one("vulndb").map_err(Cmd::Usage)?.map(PathBuf::from);
    let station = req(&a, "station")?.to_string();
    let history = path(&a, "history")?;
    let bundle = path(&a, "bundle")?;
    let rep = crate::entry::scan(&crate::entry::ScanInput {
        bundle: &bundle,
        site: &site,
        station: &station,
        vulndb: vulndb.as_deref(),
        history: &history,
        fail_on,
        now,
        lifetime_s: days.saturating_mul(86400),
    })?;
    let k = signer(req(&a, "key")?)?;
    let (b, sig) = crate::entry::sign(&rep, k.as_ref())?;
    let out = path(&a, "out")?;
    std::fs::write(&out, &b).map_err(|e| err(e.to_string()))?;
    std::fs::write(robodr_release::ops::sig_path(&out), &sig).map_err(|e| err(e.to_string()))?;
    print(json!({"verdict": rep.verdict, "worst": rep.worst(), "report": out}));
    if rep.verdict == robodr_pkg::entry::Verdict::Fail {
        return Err(Cmd::Fail(err(
            "the bundle failed the scan (report written)",
        )));
    }
    Ok(())
}
