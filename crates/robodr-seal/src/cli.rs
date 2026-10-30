//! `robodr-seal` command line (see [`USAGE`]).

use crate::luks::Luks;
use crate::tpm::{Tpm, TpmConfig};
use crate::unit::{parse_handle, Unit, UnitRecord};
use crate::{keys, policy, SealError};
use robodr_diode::cli::{argv, is_version_request, parse_args_with_switches, Args};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const USAGE: &str = "\
usage:
  robodr-seal keygen depot --out FILE          X25519 depot wrapping key (FILE, FILE.pub)
  robodr-seal keygen policy --out FILE         P-256 policy authority key (FILE, FILE.pub)
  robodr-seal policy sign --key FILE --platform P --version N --pcr I=HEX [--pcr I=HEX]...
        [--floor-nv 0xNNNNNNNN] [--last-version] --out FILE
  robodr-seal provision --owner-auth-file FILE TPM
  robodr-seal enroll --seal-dir DIR --unit U --platform P --policy-authority FILE.pub TPM
  robodr-seal enroll-fallback --seal-dir DIR --unit U --platform P --key FILE
        [--unchecked-key-location]
  robodr-seal policy install --seal-dir DIR --policy FILE TPM
  robodr-seal policy commit --seal-dir DIR TPM
  robodr-seal rewrap --depot-key FILE --rpk RPK_DIR --unit-record UNIT.json
  robodr-seal volume format --seal-dir DIR --device DEV TPM
  robodr-seal volume open --seal-dir DIR --device DEV --name NAME TPM
  robodr-seal volume format-tang --device DEV --tang-url URL --tang-thp THUMBPRINT
  robodr-seal volume open-tang --device DEV --name NAME [--slot N]
  robodr-seal volume close --name NAME
  robodr-seal erase --seal-dir DIR --trigger TRIGGER [--device DEV] [--mapper NAME]
        [--mount DIR] [--stop-unit UNIT]... [TPM]
  robodr-seal status --seal-dir DIR [TPM]
  robodr-seal --version

TPM is [--tcti TCTI] [--tools-dir DIR] [--srk 0x81NNNNNN] [--epoch-nv 0x01NNNNNN]
       [--floor-nv 0x01NNNNNN] [--timeout-ms MS] [--work-dir DIR]
(defaults: device:/dev/tpmrm0, /usr/bin, 0x81000001, 0x01500040, 0x01500041, 10000,
/run/robodr-seal; the work directory holds TPM session contexts and must be on tmpfs).

docs/SECURE-DELIVERY.md §7. A unit's UWK is created inside its TPM by enroll
and is usable only under a policy signed by the policy authority for the
unit's platform (PCR values), not revoked by the policy floor, and while
the erase epoch is unchanged. erase increments the epoch: every key sealed
to the unit is dead. Units without a TPM keep an X25519 UWK inside a
runtime volume that only the site's Tang server unlocks. rewrap is the
depot's step (§7.3): it prints the deployment wrapped_keys entry for one
unit. Keys and passphrases never appear on the command line.

erase of a unit without a TPM needs --device (its keyslots are what is
destroyed). With --mapper (and --mount, --stop-unit) erase also stops the
units, unmounts and closes the open runtime volume, or suspends it.
provision refuses a TPM whose owner or lockout authorization is empty.
The policy floor has 64 versions (0..=63); version 63 can never be revoked,
so signing it needs --last-version, and the update after it needs a new
enrolment (docs/OPERATIONS.md section 12.3).

Exit codes: 0 ok, 1 refused or error, 2 usage.";

enum Cmd {
    Usage(String),
    Fail(SealError),
}

impl From<SealError> for Cmd {
    fn from(e: SealError) -> Self {
        Cmd::Fail(e)
    }
}

fn usage(msg: &str) -> i32 {
    eprintln!("robodr-seal: {msg}\n\n{USAGE}");
    2
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

const TPM_FLAGS: [&str; 7] = [
    "tcti",
    "tools-dir",
    "srk",
    "epoch-nv",
    "floor-nv",
    "timeout-ms",
    "work-dir",
];

/// Run one command line (without the program name).
pub fn run(args: Vec<String>) -> i32 {
    if is_version_request(&args) {
        println!("robodr-seal {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
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
        "keygen" => sub(rest, &[("depot", keygen_depot), ("policy", keygen_policy)]),
        "policy" => sub(
            rest,
            &[
                ("sign", policy_sign),
                ("install", policy_install),
                ("commit", policy_commit),
            ],
        ),
        "provision" => provision(rest),
        "enroll" => enroll(rest),
        "enroll-fallback" => enroll_fallback(rest),
        "rewrap" => rewrap(rest),
        "volume" => sub(
            rest,
            &[
                ("format", volume_format),
                ("open", volume_open),
                ("format-tang", volume_format_tang),
                ("open-tang", volume_open_tang),
                ("close", volume_close),
            ],
        ),
        "erase" => erase(rest),
        "status" => status(rest),
        other => Err(Cmd::Usage(format!("unknown command {other:?}"))),
    };
    match r {
        Ok(()) => 0,
        Err(Cmd::Usage(m)) if m == "help" => {
            usage("--help is only accepted alone (robodr-seal --help)")
        }
        Err(Cmd::Usage(m)) => usage(&m),
        Err(Cmd::Fail(e)) => {
            eprintln!("robodr-seal: {e}");
            1
        }
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

fn parse(args: Vec<String>, known: &[&str], tpm: bool) -> Result<Args, Cmd> {
    parse_sw(args, known, &[], tpm)
}

fn parse_sw(args: Vec<String>, known: &[&str], switches: &[&str], tpm: bool) -> Result<Args, Cmd> {
    let mut k: Vec<&str> = known.to_vec();
    if tpm {
        k.extend_from_slice(&TPM_FLAGS);
    }
    parse_args_with_switches(args, &k, switches).map_err(Cmd::Usage)
}

fn req<'a>(a: &'a Args, f: &str) -> Result<&'a str, Cmd> {
    a.req(f).map_err(Cmd::Usage)
}

fn opt<'a>(a: &'a Args, f: &str) -> Result<Option<&'a str>, Cmd> {
    a.one(f).map_err(Cmd::Usage)
}

fn path(a: &Args, f: &str) -> Result<PathBuf, Cmd> {
    Ok(PathBuf::from(req(a, f)?))
}

fn tpm(a: &Args) -> Result<Tpm, Cmd> {
    let mut c = TpmConfig::default();
    if let Some(t) = opt(a, "tcti")? {
        c.tcti = t.into();
    }
    if let Some(d) = opt(a, "tools-dir")? {
        c.tools_dir = d.into();
    }
    if let Some(d) = opt(a, "work-dir")? {
        c.work_dir = d.into();
    }
    let h = |f: &str, top: u32| -> Result<Option<u32>, Cmd> {
        opt(a, f)?
            .map(|s| parse_handle(s, top).map_err(|e| Cmd::Usage(format!("--{f}: {}", e.detail))))
            .transpose()
    };
    if let Some(v) = h("srk", 0x81)? {
        c.srk = v;
    }
    if let Some(v) = h("epoch-nv", 0x01)? {
        c.epoch_nv = v;
    }
    if let Some(v) = h("floor-nv", 0x01)? {
        c.floor_nv = v;
    }
    if let Some(ms) = a.num::<u64>("timeout-ms").map_err(Cmd::Usage)? {
        c.timeout = Duration::from_millis(ms);
    }
    Ok(Tpm::new(c, Box::new(crate::cmd::System))?)
}

fn has_tpm_flags(a: &Args) -> bool {
    TPM_FLAGS.iter().any(|f| !a.all(f).is_empty())
}

fn keygen_depot(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["out"], false)?;
    let out = path(&a, "out")?;
    let pub_path = PathBuf::from(format!("{}.pub", out.display()));
    let k = keys::x25519_generate(&out, &pub_path)?;
    print(json!({
        "secret": out.display().to_string(),
        "public": pub_path.display().to_string(),
        "fingerprint": crate::wrap::Recipient::X25519(k.public()).fingerprint(),
    }));
    Ok(())
}

fn keygen_policy(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["out"], false)?;
    let out = path(&a, "out")?;
    let pub_path = PathBuf::from(format!("{}.pub", out.display()));
    let k = keys::policy_generate(&out, &pub_path)?;
    print(json!({
        "secret": out.display().to_string(),
        "public": pub_path.display().to_string(),
        "public_key": crate::to_hex(&k.public()),
    }));
    Ok(())
}

fn parse_pcr(s: &str) -> Result<(u8, [u8; 32]), Cmd> {
    let (i, v) = s
        .split_once('=')
        .ok_or_else(|| Cmd::Usage(format!("--pcr {s:?}: expected INDEX=HEX")))?;
    let i: u8 = i
        .parse()
        .ok()
        .filter(|i| *i <= policy::MAX_PCR)
        .ok_or_else(|| Cmd::Usage(format!("--pcr {s:?}: index 0..=23")))?;
    let b = crate::from_hex(v)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| Cmd::Usage(format!("--pcr {s:?}: value is 64 lower-case hex")))?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok((i, a))
}

fn policy_sign(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse_sw(
        args,
        &["key", "platform", "version", "pcr", "floor-nv", "out"],
        &["last-version"],
        false,
    )?;
    let version: u32 = a
        .num("version")
        .map_err(Cmd::Usage)?
        .ok_or_else(|| Cmd::Usage("--version is required".into()))?;
    if version == policy::MAX_VERSION && !a.flag("last-version") {
        return Err(Cmd::Fail(crate::invalid(format!(
            "version {v} is the policy floor's last: it can never be revoked, and the next \
             boot-chain update needs a new enrolment (erase, redefine the floor with the owner \
             authorization, enrol again). Pass --last-version to sign it anyway.",
            v = policy::MAX_VERSION
        ))));
    }
    let pcrs = a
        .all("pcr")
        .into_iter()
        .map(parse_pcr)
        .collect::<Result<Vec<_>, _>>()?;
    let floor = match opt(&a, "floor-nv")? {
        Some(s) => parse_handle(s, 0x01).map_err(|e| Cmd::Usage(e.detail))?,
        None => crate::tpm::DEFAULT_FLOOR_NV,
    };
    let out = path(&a, "out")?;
    let platform = req(&a, "platform")?;
    let key = keys::policy_load(&path(&a, "key")?)?;
    let b = policy::sign(&key, platform, version, &pcrs, floor)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .map_err(|e| crate::io_err(&out, e))?;
    std::io::Write::write_all(&mut f, &b).map_err(|e| crate::io_err(&out, e))?;
    print(json!({"policy": out.display().to_string(), "version": version}));
    Ok(())
}

/// A secret file: opened with `O_NOFOLLOW`, then checked on the open
/// descriptor (regular, not group/other accessible), bounded.
fn read_secret_file(p: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, Cmd> {
    Ok(keys::read_bounded(p, true)?)
}

fn provision(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["owner-auth-file"], true)?;
    let t = tpm(&a)?;
    let auth = read_secret_file(&path(&a, "owner-auth-file")?)?;
    let p = t.provision(&auth)?;
    print(json!({
        "defined_epoch": p.defined_epoch,
        "defined_floor": p.defined_floor,
        "created_srk": p.created_srk,
        "epoch": t.epoch()?,
        "floor_bits": t.floor_bits()?,
    }));
    Ok(())
}

fn record_json(r: &UnitRecord) -> serde_json::Value {
    serde_json::to_value(r).unwrap_or_default()
}

fn enroll(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &["seal-dir", "unit", "platform", "policy-authority"],
        true,
    )?;
    let authority = keys::policy_load_public(&path(&a, "policy-authority")?)?;
    let u = Unit::enroll_tpm(
        &path(&a, "seal-dir")?,
        req(&a, "unit")?,
        req(&a, "platform")?,
        &authority,
        tpm(&a)?,
    )?;
    print(record_json(u.record()));
    Ok(())
}

fn enroll_fallback(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse_sw(
        args,
        &["seal-dir", "unit", "platform", "key"],
        &["unchecked-key-location"],
        false,
    )?;
    let location = if a.flag("unchecked-key-location") {
        crate::unit::KeyLocation::Unchecked
    } else {
        crate::unit::KeyLocation::DmCrypt
    };
    let u = Unit::enroll_fallback(
        &path(&a, "seal-dir")?,
        req(&a, "unit")?,
        req(&a, "platform")?,
        &path(&a, "key")?,
        location,
    )?;
    print(record_json(u.record()));
    Ok(())
}

fn open_unit(a: &Args) -> Result<Unit, Cmd> {
    // TPM flags are checked before any file is read.
    let flagged = if has_tpm_flags(a) {
        Some(tpm(a)?)
    } else {
        None
    };
    let dir = path(a, "seal-dir")?;
    let rec = UnitRecord::parse(
        &std::fs::read(dir.join(crate::unit::UNIT_FILE)).map_err(|e| crate::io_err(&dir, e))?,
    )?;
    let t = match (flagged, rec.mode) {
        (Some(t), _) => Some(t),
        (None, crate::unit::Mode::Tpm) => Some(tpm(a)?),
        (None, crate::unit::Mode::Fallback) => None,
    };
    Ok(Unit::open(&dir, t)?)
}

fn policy_install(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["seal-dir", "policy"], true)?;
    let u = open_unit(&a)?;
    let p = path(&a, "policy")?;
    let b = std::fs::read(&p).map_err(|e| crate::io_err(&p, e))?;
    let c = u.install_policy(&b)?;
    print(json!({"installed": c.doc.version, "pcrs": c.pcr_list()}));
    Ok(())
}

fn policy_commit(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["seal-dir"], true)?;
    let u = open_unit(&a)?;
    let v = u.commit_policy()?;
    print(json!({"committed": v, "revoked_below": v}));
    Ok(())
}

fn rewrap(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["depot-key", "rpk", "unit-record"], false)?;
    let depot = keys::x25519_load(&path(&a, "depot-key")?)?;
    let dir = path(&a, "rpk")?;
    let mp = dir.join(robodr_pkg::rpk::MANIFEST_FILE);
    let mb = std::fs::read(&mp).map_err(|e| crate::io_err(&mp, e))?;
    let m = robodr_pkg::rpk::parse_manifest(&mb).map_err(|e| crate::invalid(e.to_string()))?;
    let digest = robodr_pkg::rpk::rpk_digest(&mb);
    let up = path(&a, "unit-record")?;
    let rec = UnitRecord::parse(&std::fs::read(&up).map_err(|e| crate::io_err(&up, e))?)?;
    let wk = crate::rpk::rewrap_for_unit(&depot, &m, &digest, &rec)?;
    print(serde_json::to_value(&wk).unwrap_or_default());
    Ok(())
}

fn volume_format(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["seal-dir", "device"], true)?;
    let u = open_unit(&a)?;
    let dev = path(&a, "device")?;
    let k = u.create_volume_key()?;
    if let Err(e) = Luks::system().format(&dev, &k[..], "robodr-sealed") {
        let _ = std::fs::remove_file(u.dir().join(crate::unit::VOLUME_WRAP_FILE));
        return Err(e.into());
    }
    print(json!({"device": dev.display().to_string(), "formatted": true}));
    Ok(())
}

fn volume_open(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["seal-dir", "device", "name"], true)?;
    let u = open_unit(&a)?;
    let k = u.volume_key()?;
    Luks::system().open(&path(&a, "device")?, req(&a, "name")?, &k[..])?;
    print(json!({"opened": format!("/dev/mapper/{}", req(&a, "name")?)}));
    Ok(())
}

fn volume_format_tang(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["device", "tang-url", "tang-thp"], false)?;
    Luks::system().format_tang(
        &path(&a, "device")?,
        req(&a, "tang-url")?,
        req(&a, "tang-thp")?,
    )?;
    print(json!({"formatted": true, "bound": "tang"}));
    Ok(())
}

fn volume_open_tang(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["device", "name", "slot"], false)?;
    let slot = a.num::<u8>("slot").map_err(Cmd::Usage)?.unwrap_or(1);
    Luks::system().open_tang(&path(&a, "device")?, req(&a, "name")?, slot)?;
    print(json!({"opened": format!("/dev/mapper/{}", req(&a, "name")?)}));
    Ok(())
}

fn volume_close(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["name"], false)?;
    Luks::system().close(req(&a, "name")?)?;
    Ok(())
}

fn erase(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(
        args,
        &[
            "seal-dir",
            "trigger",
            "device",
            "mapper",
            "mount",
            "stop-unit",
        ],
        true,
    )?;
    let u = open_unit(&a)?;
    let luks = Luks::system();
    let dev = opt(&a, "device")?.map(PathBuf::from);
    let mount = opt(&a, "mount")?
        .map(PathBuf::from)
        .filter(|m| crate::mounts::is_mount_point(m));
    let units: Vec<String> = a.all("stop-unit").into_iter().map(String::from).collect();
    let target = crate::unit::EraseTarget {
        device: dev.as_deref(),
        mapper: opt(&a, "mapper")?,
        mount: mount.as_deref(),
        stop_units: &units,
    };
    let r = u.erase(req(&a, "trigger")?, &luks, &target)?;
    print(serde_json::to_value(&r).unwrap_or_default());
    Ok(())
}

fn status(args: Vec<String>) -> Result<(), Cmd> {
    let a = parse(args, &["seal-dir"], true)?;
    let u = open_unit(&a)?;
    print(serde_json::to_value(u.status()).unwrap_or_default());
    Ok(())
}
