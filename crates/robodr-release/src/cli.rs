//! `robodr-release` command line (see [`USAGE`]).

use crate::fsio::{read_capped, Fail};
use crate::ops::{self, BundleOptions, ChainMode, SiteTrust, Target};
use robodr_blackbox::keys::public_key_path;
use robodr_blackbox::KeyFile;
use robodr_diode::cli::{argv, is_version_request, parse_args_with_switches, Args};
use robodr_pkg::bundle::ChainStep;
use robodr_pkg::common::{fingerprint, is_fingerprint, is_hex64};
use serde_json::json;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "\
usage:
  robodr-release keygen --out SECRET_KEY_FILE [--key-id ID]
  robodr-release fingerprint --key KEY_FILE
  robodr-release build rpk --spec SPEC.json --payload DIR --out-dir DIR [--seal-to DEPOT.pub]...
  robodr-release build bundle --programme P --seq N [--prev-bundle DIR | --prev-hash HEX]
        --rpk DIR [--rpk DIR]... TRUST [--parity M [--parity-group K] [--shard-size BYTES]]
        [--created-at SECS] [--now SECS] --out DIR
  robodr-release sign --key SECRET_KEY_FILE --target RPK_DIR|BUNDLE_DIR|DEPLOYMENT.json TRUST
        [--now SECS]
  robodr-release sign --key SECRET_KEY_FILE --target TRUST.json [TRUST]
  robodr-release verify rpk --dir DIR TRUST [--now SECS]
  robodr-release verify bundle --dir DIR TRUST CHAIN [--now SECS]
  robodr-release verify trust TRUST [--init-anchor | --commit] [--now SECS]
  robodr-release verify deployment --file DEPLOYMENT.json TRUST [--now SECS]
  robodr-release import --from MEDIA_BUNDLE_DIR --to NEW_DIR TRUST CHAIN [--now SECS]
  robodr-release repair --dir BUNDLE_DIR TRUST [--now SECS]
  robodr-release --version

TRUST is --trust TRUST.json --root FPR [--root FPR]... --site SITE
      (--trust-anchor ANCHOR.json | --no-trust-anchor)
CHAIN is --genesis | --after SEQ:HASH | --state FILE [--genesis] [--commit]

Formats: docs/SECURE-DELIVERY.md §3 (robodr-pkg/1, robodr-bundle/1,
robodr-deployment/1, robodr-delivery-trust/1, robodr-sigset/1).

Keys are robodr-blackbox Ed25519 key files (keygen writes FILE, mode 0600,
and FILE.pub). sign adds one signature to the document's detached signature
file (MANIFEST.sig, bundle.sig, or FILE.sig); a quorum is reached by running
it once per key holder. sign checks the document first (an RPK's or bundle's
files must match it exactly, every RPK in a bundle must verify) and refuses
if any signature already present, or its own, is not valid for it.

Trust. A trust file is accepted only if its roots are exactly the --root
fingerprints and its site the --site given (both pinned out of band), the
root quorum signed it and it has not expired. The site keeps one trust
anchor (ANCHOR.json and ANCHOR.json.sig on trusted storage, shared by all
programmes): the presented --trust must be the anchor or a valid rotation
of it (newer version signed by the old and new root quorums, revocations
and floors kept), so an older or another site's trust file is refused.
`verify trust --init-anchor` creates the anchor once; `verify trust
--commit` (and `verify bundle`/`import` --commit) advance it to an
accepted rotation. --no-trust-anchor drops that protection and must be
given explicitly; it cannot be combined with --state.

verify prints a JSON summary and exits 0, or prints the refusal
(`refused (<code>): <detail>`) and exits 1. The chain mode is mandatory:
--genesis (first bundle of the programme here), --after SEQ:HASH (the
accepted head, named by the operator) or --state FILE (a
robodr-bundle-chain/1 head; with --genesis it may be absent; --commit
writes the new head after an accepted bundle). --now defaults to the
system clock (Unix seconds); a clock before 1970 is an error.

build rpk --seal-to (one per site depot wrapping key, robodr-seal keygen
depot) builds a sealed RPK (docs/SECURE-DELIVERY.md §7.2): every payload
file but the SBOM is encrypted under a fresh content key that is written
only wrapped to those depot keys; the depots re-wrap it per unit.

import copies a bundle from untrusted media into NEW_DIR (created; on
trusted storage) and verifies the copy before publishing it: use only
NEW_DIR afterwards, never the media (docs/SECURE-DELIVERY.md §3.5).

Exit codes: 0 ok, 1 refused or error, 2 usage.";

fn usage(msg: &str) -> i32 {
    eprintln!("robodr-release: {msg}\n\n{USAGE}");
    2
}

fn fail(e: Fail) -> i32 {
    eprintln!("robodr-release: {e}");
    1
}

/// Unix seconds of `t`; a time before the epoch is an error, never 0
/// (0 would make every expiry lie in the future; 13a review finding 9).
fn unix_secs(t: std::time::SystemTime) -> Result<u64, Fail> {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Fail::Io("the system clock is before 1970; refusing (pass --now SECS)".into()))
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
    // Help only as the whole command line: a stray -h spliced into a
    // verify command must never turn a refusal into exit 0 (13a review
    // finding 8).
    if matches!(args.as_slice(), [a] if a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }
    let mut it = args.into_iter();
    let Some(cmd) = it.next() else {
        return usage("missing command");
    };
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
        "import" => import(rest),
        other => Err(Cmd::Usage(format!("unknown command {other:?}"))),
    };
    match r {
        Ok(()) => 0,
        Err(Cmd::Usage(m)) if m == "help" => {
            usage("--help is only accepted alone (robodr-release --help)")
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

/// Flags of the TRUST argument group.
const TRUST_FLAGS: [&str; 4] = ["trust", "root", "site", "trust-anchor"];
const TRUST_SWITCHES: [&str; 1] = ["no-trust-anchor"];

/// `known` plus the TRUST flags.
fn with_trust<'a>(known: &[&'a str]) -> Vec<&'a str> {
    let mut v = known.to_vec();
    v.extend(TRUST_FLAGS);
    v
}

fn site(a: &Args) -> Result<String, Cmd> {
    let s = req(a, "site")?;
    if !robodr_pkg::common::is_label(s) {
        return Err(Cmd::Usage(format!("--site {s:?} is not a site label")));
    }
    Ok(s.to_string())
}

/// The site trust of the TRUST argument group: anchored (`--trust-anchor`)
/// or, explicitly, not (`--no-trust-anchor`); exactly one is required.
fn trust(a: &Args, now: u64) -> Result<SiteTrust, Cmd> {
    let presented = PathBuf::from(req(a, "trust")?);
    let pins = pins(a)?;
    let site = site(a)?;
    match (opt(a, "trust-anchor")?, a.flag("no-trust-anchor")) {
        (Some(anchor), false) => Ok(SiteTrust::anchored(
            &presented,
            Path::new(anchor),
            &pins,
            &site,
            now,
        )?),
        (None, true) => Ok(SiteTrust::unanchored(&presented, &pins, &site, now)?),
        _ => Err(Cmd::Usage(
            "exactly one of --trust-anchor ANCHOR.json (the site's accepted trust file) or \
             --no-trust-anchor (no rollback protection, explicitly) is required"
                .into(),
        )),
    }
}

fn now(a: &Args) -> Result<u64, Cmd> {
    match num::<u64>(a, "now")? {
        Some(n) => Ok(n),
        None => Ok(unix_secs(std::time::SystemTime::now())?),
    }
}

/// The CHAIN argument group (and `--commit`).
fn chain_mode(a: &Args) -> Result<(ChainMode, Option<PathBuf>, bool), Cmd> {
    let genesis = a.flag("genesis");
    let commit = a.flag("commit");
    let state = opt(a, "state")?.map(PathBuf::from);
    let after = opt(a, "after")?;
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
    if state.is_some() && a.flag("no-trust-anchor") {
        return Err(Cmd::Usage(
            "--state needs the site's --trust-anchor (a chain state never vouches for a newer \
             trust file by itself)"
                .into(),
        ));
    }
    Ok((mode, state, commit))
}

fn keygen(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["out", "key-id"], &[])?;
    let out = PathBuf::from(req(&a, "out")?);
    if let Some(id) = opt(&a, "key-id")? {
        // The delivery formats' key-id rule (stricter than the key file's).
        if !robodr_pkg::common::is_key_id(id) {
            return Err(Cmd::Usage(format!(
                "--key-id {id:?} is not [A-Za-z0-9._:-]{{1,64}}"
            )));
        }
    }
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
    let a = parse(args, &["spec", "payload", "out-dir", "seal-to"], &[])?;
    let spec = ops::parse_spec(&read_capped(
        Path::new(req(&a, "spec")?),
        ops::MAX_SPEC_BYTES,
    )?)?;
    let mut depots = Vec::new();
    for p in a.all("seal-to") {
        depots.push(
            robodr_seal::keys::x25519_load_public(Path::new(p))
                .map_err(|e| Cmd::Fail(Fail::Io(format!("--seal-to {p}: {e}"))))?,
        );
    }
    let b = ops::build_rpk_with(
        &spec,
        Path::new(req(&a, "payload")?),
        Path::new(req(&a, "out-dir")?),
        (!depots.is_empty()).then_some(depots.as_slice()),
    )?;
    print(json!({
        "rpk": b.dir.display().to_string(),
        "digest": b.digest,
        "name": b.manifest.name,
        "serial": b.manifest.version.serial,
        "files": b.manifest.content.len(),
        "chunks": b.manifest.chunks.len(),
        "sealed": b.manifest.is_sealed(),
        "signed": false,
    }));
    Ok(())
}

fn build_bundle(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &with_trust(&[
            "programme",
            "seq",
            "prev-bundle",
            "prev-hash",
            "rpk",
            "parity",
            "parity-group",
            "shard-size",
            "created-at",
            "now",
            "out",
        ]),
        &TRUST_SWITCHES,
    )?;
    let n = now(&a)?;
    let t = trust(&a, n)?;
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
    let b = ops::build_bundle(&BundleOptions {
        programme,
        seq,
        prev_hash,
        created_at: num(&a, "created-at")?.unwrap_or(n),
        rpks,
        trust: &t.trust,
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
    let a = parse(
        args,
        &with_trust(&["key", "target", "now"]),
        &TRUST_SWITCHES,
    )?;
    let kpath = Path::new(req(&a, "key")?);
    let k =
        KeyFile::load_secret(kpath).map_err(|e| Fail::Io(format!("{}: {e}", kpath.display())))?;
    let signer = k
        .ed25519_signing_key()
        .map_err(|e| Fail::Io(format!("{}: {e} (only ed25519 keys sign)", kpath.display())))?;
    let target = Target::detect(Path::new(req(&a, "target")?))?;
    let n = now(&a)?;
    let t = match (&target, opt(&a, "trust")?) {
        (Target::Trust(_), None) => {
            if !a.all("root").is_empty() || opt(&a, "site")?.is_some() {
                return Err(Cmd::Usage("--root/--site without --trust".into()));
            }
            None
        }
        _ => Some(trust(&a, n)?),
    };
    let (sig, n) = ops::sign(&target, &signer, t.as_ref().map(|t| &t.trust), n)?;
    print(json!({
        "signature_file": sig.display().to_string(),
        "signatures": n,
        "key_id": robodr_blackbox::Signer::key_id(&signer),
        "fingerprint": fingerprint(&signer.public_key()),
    }));
    Ok(())
}

fn verify_rpk(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &with_trust(&["dir", "now"]), &TRUST_SWITCHES)?;
    let n = now(&a)?;
    let t = trust(&a, n)?;
    let v = ops::verify_rpk_dir(Path::new(req(&a, "dir")?), &t, n)?;
    print(json!({
        "verified": "rpk",
        "programme": v.programme,
        "trust_version": t.file().version,
        "trust_anchored": t.anchor.is_some(),
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
        &with_trust(&["dir", "now", "after", "state"]),
        &["genesis", "commit", "no-trust-anchor"],
    )?;
    let (mode, state, commit) = chain_mode(&a)?;
    let n = now(&a)?;
    let t = trust(&a, n)?;
    let r = ops::verify_bundle_dir(Path::new(req(&a, "dir")?), &t, &mode, n)?;
    let committed = commit_after(&t, &state, commit, &r)?;
    print(bundle_report("bundle", &t, &r, committed, None));
    Ok(())
}

/// Write the chain head (and advance the trust anchor) after an accepted
/// next bundle when `--commit` was given.
fn commit_after(
    t: &SiteTrust,
    state: &Option<PathBuf>,
    commit: bool,
    r: &ops::BundleReport,
) -> Result<bool, Cmd> {
    if let (true, Some(p), ChainStep::Next) = (commit, state, &r.step) {
        ops::commit_chain(p, &r.bundle, t)?;
        return Ok(true);
    }
    Ok(false)
}

fn bundle_report(
    what: &str,
    t: &SiteTrust,
    r: &ops::BundleReport,
    committed: bool,
    copy: Option<&Path>,
) -> serde_json::Value {
    let mut v = json!({
        "verified": what,
        "programme": r.bundle.manifest.programme,
        "bundle_seq": r.bundle.manifest.bundle_seq,
        "bundle_hash": r.bundle.hash,
        "chain": match r.step { ChainStep::Next => "next", ChainStep::AlreadyAccepted => "already_accepted" },
        "state_committed": committed,
        "trust_version": t.file().version,
        "trust_anchored": t.anchor.is_some(),
        "release_signers": r.bundle.signers.of(robodr_pkg::sig::Role::Release),
        "rpks": r.rpks.iter().map(|v| json!({
            "name": v.manifest.name,
            "serial": v.manifest.version.serial,
            "digest": v.digest,
        })).collect::<Vec<_>>(),
    });
    if let Some(c) = copy {
        v["verified_copy"] = json!(c.display().to_string());
    }
    v
}

fn import(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &with_trust(&["from", "to", "now", "after", "state"]),
        &["genesis", "commit", "no-trust-anchor"],
    )?;
    let (mode, state, commit) = chain_mode(&a)?;
    let n = now(&a)?;
    let t = trust(&a, n)?;
    let to = PathBuf::from(req(&a, "to")?);
    let r = ops::import_bundle(Path::new(req(&a, "from")?), &to, &t, &mode, n)?;
    let committed = commit_after(&t, &state, commit, &r)?;
    print(bundle_report("import", &t, &r, committed, Some(&to)));
    Ok(())
}

fn verify_trust(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &with_trust(&["now"]),
        &["no-trust-anchor", "init-anchor", "commit"],
    )?;
    let n = now(&a)?;
    let (init, commit) = (a.flag("init-anchor"), a.flag("commit"));
    if init && commit {
        return Err(Cmd::Usage("--init-anchor or --commit, not both".into()));
    }
    if init && a.flag("no-trust-anchor") {
        return Err(Cmd::Usage(
            "--init-anchor creates the --trust-anchor; not with --no-trust-anchor".into(),
        ));
    }
    let (v, anchored, written) = if init {
        let anchor = opt(&a, "trust-anchor")?
            .ok_or_else(|| Cmd::Usage("--init-anchor needs --trust-anchor ANCHOR.json".into()))?;
        let v = ops::init_anchor(
            Path::new(req(&a, "trust")?),
            Path::new(anchor),
            &pins(&a)?,
            &site(&a)?,
            n,
        )?;
        (v, true, true)
    } else {
        let t = trust(&a, n)?;
        if commit && t.anchor.is_none() {
            return Err(Cmd::Usage("--commit needs --trust-anchor".into()));
        }
        let written = commit && ops::commit_anchor(&t)?;
        let anchored = t.anchor.is_some();
        (t.trust, anchored, written)
    };
    print(json!({
        "verified": "trust",
        "site": v.file().site,
        "version": v.file().version,
        "expires_at": v.file().expires_at,
        "digest": v.digest,
        "roots": v.root_fingerprints(),
        "trust_anchored": anchored,
        "anchor_written": written,
    }));
    Ok(())
}

fn verify_deployment(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &with_trust(&["file", "now"]), &TRUST_SWITCHES)?;
    let n = now(&a)?;
    let t = trust(&a, n)?;
    let v = ops::verify_deployment_file(Path::new(req(&a, "file")?), &t, n)?;
    print(json!({
        "verified": "deployment",
        "deployment_id": v.deployment.deployment_id,
        "deployment_seq": v.deployment.deployment_seq,
        "ring": v.deployment.ring,
        "digest": v.digest,
        "trust_version": t.file().version,
        "trust_anchored": t.anchor.is_some(),
    }));
    Ok(())
}

fn repair(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &with_trust(&["dir", "now"]), &TRUST_SWITCHES)?;
    let n = now(&a)?;
    let t = trust(&a, n)?;
    let rebuilt = ops::repair_bundle(Path::new(req(&a, "dir")?), &t)?;
    print(json!({"rebuilt": rebuilt}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    /// 13a review finding 9: a clock before 1970 fails closed (it used to
    /// read as 0, before every expiry).
    #[test]
    fn a_clock_before_the_epoch_is_refused() {
        assert_eq!(unix_secs(UNIX_EPOCH + Duration::from_secs(5)).unwrap(), 5);
        assert!(unix_secs(UNIX_EPOCH - Duration::from_secs(1)).is_err());
    }
}
