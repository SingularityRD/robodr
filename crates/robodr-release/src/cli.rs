//! `robodr-release` command line (see [`USAGE`]).

use crate::fsio::{read_capped, Fail};
use crate::ops::{self, BundleOptions, ChainMode, Target};
use robodr_blackbox::keys::public_key_path;
use robodr_blackbox::KeyFile;
use robodr_diode::cli::{argv, is_version_request, parse_args_with_switches, Args};
use robodr_pkg::bundle::ChainStep;
use robodr_pkg::common::{fingerprint, is_fingerprint, is_hex64};
use robodr_pkg::trust::VerifiedTrust;
use serde_json::json;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "\
usage:
  robodr-release keygen --out SECRET_KEY_FILE [--key-id ID]
  robodr-release fingerprint --key KEY_FILE
  robodr-release build rpk --spec SPEC.json --payload DIR --out-dir DIR
  robodr-release build bundle --programme P --seq N [--prev-bundle DIR | --prev-hash HEX]
        --rpk DIR [--rpk DIR]... --trust TRUST.json --root FPR [--root FPR]...
        [--parity M [--parity-group K] [--shard-size BYTES]] [--created-at SECS]
        [--now SECS] --out DIR
  robodr-release sign --key SECRET_KEY_FILE --target RPK_DIR|BUNDLE_DIR|TRUST.json|DEPLOYMENT.json
  robodr-release verify rpk --dir DIR --trust TRUST.json --root FPR... [--now SECS]
  robodr-release verify bundle --dir DIR --trust TRUST.json --root FPR...
        (--genesis | --after SEQ:HASH | --state FILE [--genesis] [--commit]) [--now SECS]
  robodr-release verify trust --trust TRUST.json --root FPR... [--next TRUST2.json]
  robodr-release verify deployment --file DEPLOYMENT.json --trust TRUST.json --root FPR...
        [--now SECS]
  robodr-release repair --dir BUNDLE_DIR --trust TRUST.json --root FPR...
  robodr-release --version

Formats: docs/SECURE-DELIVERY.md §3 (robodr-pkg/1, robodr-bundle/1,
robodr-deployment/1, robodr-delivery-trust/1, robodr-sigset/1).

Keys are robodr-blackbox Ed25519 key files (keygen writes FILE, mode 0600,
and FILE.pub). sign adds one signature to the document's detached signature
file (MANIFEST.sig, bundle.sig, or FILE.sig); a quorum is reached by running
it once per key holder. sign checks the document first (an RPK's or bundle's
files must match it exactly). A trust file is accepted only if its roots are
exactly the --root fingerprints given (pinned out of band) and the root
quorum signed it; --next checks a rotation to a newer trust file.

verify prints a JSON summary and exits 0, or prints the refusal
(`refused (<code>): <detail>`) and exits 1. The chain mode is mandatory:
--genesis (first bundle of the programme here), --after SEQ:HASH (the
accepted head, named by the operator) or --state FILE (a
robodr-bundle-chain/1 head; with --genesis it may be absent; --commit
writes the new head after an accepted bundle). --now defaults to the
system clock (Unix seconds).

Exit codes: 0 ok, 1 refused or error, 2 usage.";

fn usage(msg: &str) -> i32 {
    eprintln!("robodr-release: {msg}\n\n{USAGE}");
    2
}

fn fail(e: Fail) -> i32 {
    eprintln!("robodr-release: {e}");
    1
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn print(v: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
}

/// Entry point for the binary: returns the exit code.
pub fn main_with_env() -> i32 {
    match argv() {
        Ok(a) => run(a),
        Err(e) => usage(&e),
    }
}

/// Run one command line (without the program name).
pub fn run(args: Vec<String>) -> i32 {
    if is_version_request(&args) {
        println!("robodr-release {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let mut it = args.into_iter();
    let Some(cmd) = it.next() else {
        return usage("missing command");
    };
    if cmd == "--help" || cmd == "-h" {
        println!("{USAGE}");
        return 0;
    }
    let rest: Vec<String> = it.collect();
    let r = match cmd.as_str() {
        "keygen" => keygen(rest),
        "fingerprint" => fingerprint_cmd(rest),
        "build" => sub(rest, &[("rpk", build_rpk), ("bundle", build_bundle)]),
        "sign" => sign(rest),
        "verify" => sub(
            rest,
            &[
                ("rpk", verify_rpk),
                ("bundle", verify_bundle),
                ("trust", verify_trust),
                ("deployment", verify_deployment),
            ],
        ),
        "repair" => repair(rest),
        other => Err(Cmd::Usage(format!("unknown command {other:?}"))),
    };
    match r {
        Ok(()) => 0,
        Err(Cmd::Usage(m)) if m == "help" => {
            println!("{USAGE}");
            0
        }
        Err(Cmd::Usage(m)) => usage(&m),
        Err(Cmd::Fail(e)) => fail(e),
    }
}

enum Cmd {
    Usage(String),
    Fail(Fail),
}

impl From<Fail> for Cmd {
    fn from(e: Fail) -> Self {
        Cmd::Fail(e)
    }
}

impl From<robodr_pkg::Refusal> for Cmd {
    fn from(e: robodr_pkg::Refusal) -> Self {
        Cmd::Fail(Fail::Refused(e))
    }
}

type Handler = fn(Vec<String>) -> Result<(), Cmd>;

fn sub(args: Vec<String>, table: &[(&str, Handler)]) -> Result<(), Cmd> {
    let mut it = args.into_iter();
    let s = it
        .next()
        .ok_or_else(|| Cmd::Usage("missing subcommand".into()))?;
    let h = table
        .iter()
        .find(|(n, _)| *n == s)
        .ok_or_else(|| Cmd::Usage(format!("unknown subcommand {s:?}")))?
        .1;
    h(it.collect())
}

fn parse(args: Vec<String>, known: &[&str], switches: &[&str]) -> Result<Args, Cmd> {
    parse_args_with_switches(args, known, switches).map_err(Cmd::Usage)
}

fn req<'a>(a: &'a Args, f: &str) -> Result<&'a str, Cmd> {
    a.req(f).map_err(Cmd::Usage)
}

fn opt<'a>(a: &'a Args, f: &str) -> Result<Option<&'a str>, Cmd> {
    a.one(f).map_err(Cmd::Usage)
}

fn num<T: std::str::FromStr>(a: &Args, f: &str) -> Result<Option<T>, Cmd> {
    a.num(f).map_err(Cmd::Usage)
}

fn pins(a: &Args) -> Result<Vec<String>, Cmd> {
    let p: Vec<String> = a.all("root").into_iter().map(String::from).collect();
    if p.is_empty() {
        return Err(Cmd::Usage(
            "at least one --root FINGERPRINT is required".into(),
        ));
    }
    if let Some(bad) = p.iter().find(|f| !is_fingerprint(f)) {
        return Err(Cmd::Usage(format!("--root {bad:?} is not sha256:<64 hex>")));
    }
    Ok(p)
}

fn trust(a: &Args) -> Result<VerifiedTrust, Cmd> {
    Ok(ops::load_trust(Path::new(req(a, "trust")?), &pins(a)?)?)
}

fn now(a: &Args) -> Result<u64, Cmd> {
    Ok(num::<u64>(a, "now")?.unwrap_or_else(now_secs))
}

fn keygen(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["out", "key-id"], &[])?;
    let out = PathBuf::from(req(&a, "out")?);
    let k = KeyFile::generate_ed25519(opt(&a, "key-id")?).map_err(|e| Fail::Io(e.to_string()))?;
    let pub_path = public_key_path(&out);
    let public = k.to_public().map_err(|e| Fail::Io(e.to_string()))?;
    k.write_new(&out).map_err(|e| Fail::Io(e.to_string()))?;
    public
        .write_new(&pub_path)
        .map_err(|e| Fail::Io(e.to_string()))?;
    let p = k
        .public_key()
        .ok_or_else(|| Fail::Io("no public key".into()))?;
    print(json!({
        "secret_key_file": out.display().to_string(),
        "public_key_file": pub_path.display().to_string(),
        "key_id": k.key_id,
        "fingerprint": fingerprint(&p),
    }));
    Ok(())
}

fn fingerprint_cmd(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["key"], &[])?;
    let path = Path::new(req(&a, "key")?);
    let k = KeyFile::load_public(path)
        .or_else(|_| KeyFile::load_secret(path))
        .map_err(|e| Fail::Io(format!("{}: {e}", path.display())))?;
    let p = k
        .public_key()
        .ok_or_else(|| Fail::Io("not an Ed25519 key file".into()))?;
    print(json!({"key_id": k.key_id, "fingerprint": fingerprint(&p)}));
    Ok(())
}

fn build_rpk(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["spec", "payload", "out-dir"], &[])?;
    let spec = ops::parse_spec(&read_capped(
        Path::new(req(&a, "spec")?),
        ops::MAX_SPEC_BYTES,
    )?)?;
    let b = ops::build_rpk(
        &spec,
        Path::new(req(&a, "payload")?),
        Path::new(req(&a, "out-dir")?),
    )?;
    print(json!({
        "rpk": b.dir.display().to_string(),
        "digest": b.digest,
        "name": b.manifest.name,
        "serial": b.manifest.version.serial,
        "files": b.manifest.content.len(),
        "chunks": b.manifest.chunks.len(),
        "signed": false,
    }));
    Ok(())
}

fn build_bundle(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &[
            "programme",
            "seq",
            "prev-bundle",
            "prev-hash",
            "rpk",
            "trust",
            "root",
            "parity",
            "parity-group",
            "shard-size",
            "created-at",
            "now",
            "out",
        ],
        &[],
    )?;
    let t = trust(&a)?;
    let seq: u64 = num(&a, "seq")?.ok_or_else(|| Cmd::Usage("--seq is required".into()))?;
    let programme = req(&a, "programme")?.to_string();
    let prev_hash = match (opt(&a, "prev-bundle")?, opt(&a, "prev-hash")?) {
        (Some(_), Some(_)) => {
            return Err(Cmd::Usage("--prev-bundle or --prev-hash, not both".into()))
        }
        (Some(d), None) => {
            let (h, s, p) = ops::bundle_head(Path::new(d))?;
            if s.checked_add(1) != Some(seq) || p != programme {
                return Err(Cmd::Usage(format!(
                    "--prev-bundle is bundle {s} of {p}; this is bundle {seq} of {programme}"
                )));
            }
            Some(h)
        }
        (None, Some(h)) if is_hex64(h) => Some(h.to_string()),
        (None, Some(_)) => return Err(Cmd::Usage("--prev-hash is not 64 lower-case hex".into())),
        (None, None) => None,
    };
    let rpks: Vec<PathBuf> = a.all("rpk").into_iter().map(PathBuf::from).collect();
    if rpks.is_empty() {
        return Err(Cmd::Usage("at least one --rpk".into()));
    }
    let parity = match num::<usize>(&a, "parity")? {
        None | Some(0) => None,
        Some(m) => Some((
            num::<usize>(&a, "parity-group")?.unwrap_or(32),
            m,
            num::<u64>(&a, "shard-size")?.unwrap_or(64 * 1024),
        )),
    };
    let n = now(&a)?;
    let b = ops::build_bundle(&BundleOptions {
        programme,
        seq,
        prev_hash,
        created_at: num(&a, "created-at")?.unwrap_or(n),
        rpks,
        trust: &t,
        now: n,
        parity,
        out: PathBuf::from(req(&a, "out")?),
    })?;
    print(json!({
        "bundle": b.dir.display().to_string(),
        "programme": b.manifest.programme,
        "bundle_seq": b.manifest.bundle_seq,
        "rpks": b.manifest.rpks.len(),
        "files": b.manifest.files.len(),
        "parity": b.manifest.parity.is_some(),
        "signed": false,
    }));
    Ok(())
}

fn sign(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["key", "target"], &[])?;
    let kpath = Path::new(req(&a, "key")?);
    let k =
        KeyFile::load_secret(kpath).map_err(|e| Fail::Io(format!("{}: {e}", kpath.display())))?;
    let signer = k
        .ed25519_signing_key()
        .map_err(|e| Fail::Io(format!("{}: {e} (only ed25519 keys sign)", kpath.display())))?;
    let target = Target::detect(Path::new(req(&a, "target")?))?;
    let (sig, n) = ops::sign(&target, &signer)?;
    print(json!({
        "signature_file": sig.display().to_string(),
        "signatures": n,
        "key_id": robodr_blackbox::Signer::key_id(&signer),
        "fingerprint": fingerprint(&signer.public_key()),
    }));
    Ok(())
}

fn verify_rpk(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["dir", "trust", "root", "now"], &[])?;
    let t = trust(&a)?;
    let v = ops::verify_rpk_dir(Path::new(req(&a, "dir")?), &t, now(&a)?)?;
    print(json!({
        "verified": "rpk",
        "name": v.manifest.name,
        "serial": v.manifest.version.serial,
        "digest": v.digest,
        "release_signers": v.signers.of(robodr_pkg::sig::Role::Release),
    }));
    Ok(())
}

fn verify_bundle(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &["dir", "trust", "root", "now", "after", "state"],
        &["genesis", "commit"],
    )?;
    let genesis = a.flag("genesis");
    let commit = a.flag("commit");
    let state = opt(&a, "state")?.map(PathBuf::from);
    let after = opt(&a, "after")?;
    let mode = match (genesis, after, &state) {
        (false, Some(s), None) => {
            let (seq, hash) = s
                .split_once(':')
                .ok_or_else(|| Cmd::Usage("--after SEQ:HASH".into()))?;
            let seq: u64 = seq
                .parse()
                .map_err(|_| Cmd::Usage("--after SEQ:HASH".into()))?;
            if !is_hex64(hash) || seq == 0 {
                return Err(Cmd::Usage(
                    "--after SEQ:HASH (HASH: 64 lower-case hex)".into(),
                ));
            }
            ChainMode::After {
                seq,
                hash: hash.into(),
            }
        }
        (true, None, None) => ChainMode::Genesis,
        (g, None, Some(p)) => match (g, std::fs::symlink_metadata(p).is_ok()) {
            (false, true) => ChainMode::State(p.clone()),
            (true, false) => ChainMode::Genesis,
            (false, false) => {
                return Err(Cmd::Usage(format!(
                    "{}: no chain state; pass --genesis for the first bundle",
                    p.display()
                )))
            }
            (true, true) => {
                return Err(Cmd::Usage(format!(
                    "{}: a chain state exists; --genesis would restart the chain",
                    p.display()
                )))
            }
        },
        _ => {
            return Err(Cmd::Usage(
                "exactly one chain mode: --genesis, --after SEQ:HASH or --state FILE".into(),
            ))
        }
    };
    if commit && state.is_none() {
        return Err(Cmd::Usage("--commit needs --state".into()));
    }
    let t = trust(&a)?;
    let r = ops::verify_bundle_dir(Path::new(req(&a, "dir")?), &t, &mode, now(&a)?)?;
    let mut committed = false;
    if let (true, Some(p), ChainStep::Next) = (commit, &state, &r.step) {
        ops::commit_chain(p, &r.bundle)?;
        committed = true;
    }
    print(json!({
        "verified": "bundle",
        "programme": r.bundle.manifest.programme,
        "bundle_seq": r.bundle.manifest.bundle_seq,
        "bundle_hash": r.bundle.hash,
        "chain": match r.step { ChainStep::Next => "next", ChainStep::AlreadyAccepted => "already_accepted" },
        "state_committed": committed,
        "release_signers": r.bundle.signers.of(robodr_pkg::sig::Role::Release),
        "rpks": r.rpks.iter().map(|v| json!({
            "name": v.manifest.name,
            "serial": v.manifest.version.serial,
            "digest": v.digest,
        })).collect::<Vec<_>>(),
    }));
    Ok(())
}

fn verify_trust(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["trust", "root", "next"], &[])?;
    let p = pins(&a)?;
    let v = match opt(&a, "next")? {
        None => ops::load_trust(Path::new(req(&a, "trust")?), &p)?,
        Some(n) => ops::load_trust_update(Path::new(req(&a, "trust")?), &p, Path::new(n))?,
    };
    print(json!({
        "verified": "trust",
        "site": v.file().site,
        "version": v.file().version,
        "digest": v.digest,
        "roots": v.root_fingerprints(),
    }));
    Ok(())
}

fn verify_deployment(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["file", "trust", "root", "now"], &[])?;
    let t = trust(&a)?;
    let v = ops::verify_deployment_file(Path::new(req(&a, "file")?), &t, now(&a)?)?;
    print(json!({
        "verified": "deployment",
        "deployment_id": v.deployment.deployment_id,
        "deployment_seq": v.deployment.deployment_seq,
        "ring": v.deployment.ring,
        "digest": v.digest,
    }));
    Ok(())
}

fn repair(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["dir", "trust", "root"], &[])?;
    let t = trust(&a)?;
    let rebuilt = ops::repair_bundle(Path::new(req(&a, "dir")?), &t)?;
    print(json!({"rebuilt": rebuilt}));
    Ok(())
}
