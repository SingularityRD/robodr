//! `robodr-blackbox`: key and evidence tooling for the black-box recorder.
//!
//! ```text
//! robodr-blackbox keygen     --out FILE [--alg ed25519|hmac --allow-hmac] [--key-id ID]
//!                            [--pub-out FILE] [--device ID]
//! robodr-blackbox export-pub KEYFILE [--out FILE]
//! robodr-blackbox verify     DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
//!                            [--device ID] [--allow-hmac] [--allow-mixed-algorithms]
//!                            [--strict] [--json]
//! robodr-blackbox verify     BUNDLE --keyring FILE [--keyring FILE]... [--device ID]
//!                            [--signing-key ID] [--allow-hmac] [--allow-mixed-algorithms]
//!                            [--strict] [--json]
//! robodr-blackbox rotate     DIR --old-key FILE --new-key FILE --device ID
//!                            [--previous-keys FILE]... [--tpm-sidecar FILE]
//!                            [--boot-id ID] [--reason TEXT]
//!                            [--allow-hmac]
//! robodr-blackbox inspect    DIR|SEGMENT [--json] [--limit N]
//! robodr-blackbox tpm-anchor-init  --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
//!                            [--owner-auth-file FILE] [--index-auth-file FILE]
//! robodr-blackbox tpm-anchor-check --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
//!                            [--index-auth-file FILE]
//! robodr-blackbox anchor-mark DIR --key FILE --unit ID [--out FILE] [--allow-hmac]
//! robodr-blackbox export-pending DIR --key FILE --device ID --out-dir DIR
//!                            [--previous-keys FILE]... [--max-records N] [--max-bytes N]
//!                            [--max-bundles N] [--allow-hmac]
//! robodr-blackbox backup create  --out FILE|- [--root DIR] [--include-keys]
//! robodr-blackbox backup verify  FILE
//! robodr-blackbox backup restore FILE [--root DIR] [--spool-ready]
//!                            [--evidence-to DIR] [--dry-run]
//! ```
//!
//! **Legacy HMAC keys are refused by default** (symmetric: whoever can
//! verify can also forge). Every subcommand that loads a key accepts one
//! only with `--allow-hmac` (and then warns): `keygen --alg hmac`, `verify`
//! with an HMAC key in a `--keyring`, `rotate` from an HMAC key (the way
//! off it), `anchor-mark`. `rotate` never rotates *to* an HMAC key.
//!
//! - `keygen` writes a new key. Default `--alg ed25519`: the secret seed
//!   file (`robodr-blackbox-key/v2`, mode 0600) at `--out` and the public
//!   key file (mode 0644, safe to distribute) at `--pub-out`, default
//!   `<out>.pub`. `--alg hmac --allow-hmac` writes a legacy symmetric HMAC-SHA256 key
//!   (`robodr-blackbox-key/v1`, 0600, no public half) and warns. Nothing
//!   is ever overwritten or written through a symlink; if either target
//!   exists nothing is written. It prints the key id, never the secret.
//!   `--device ID` binds the key to that unit (`device_id` in both files):
//!   verifiers then accept it only for chains of that device.
//! - `export-pub` writes (or prints) the public key file of an Ed25519
//!   secret key file. HMAC keys have no public half and are refused.
//! - `verify` checks a log directory with every key in the given key or
//!   keyring files (so a log spanning a key rotation verifies). Public key
//!   files are accepted whatever their mode; files holding a secret are
//!   refused if group or others can access them or if they are owned by
//!   another user (root excepted). `--checkpoint` is a trusted checkpoint
//!   held off the unit; without it the directory's own `checkpoint.json`
//!   is used. Each record is checked under the key its chain names (see
//!   `robodr_blackbox::verify`), never under "any key given". Mixing HMAC
//!   and Ed25519 keys is refused unless `--allow-mixed-algorithms` (needed
//!   only for a log that rotated from a legacy HMAC key to Ed25519).
//!   Given a **file** instead of a directory, `verify` checks an `RBBXBND1`
//!   export bundle (e.g. one downloaded through the control-plane evidence
//!   API, reassembled from its chunks): hashes, signatures, chain linkage
//!   from its anchor, chain id and `--device`; `--signing-key ID` names
//!   the key that signs its first record (the manifest's
//!   `chain.signing_key.key_id`; needed only for a bundle that starts after
//!   a key rotation; its algorithm is the keyring entry's). The anchor is
//!   reported as unverified (info): compare it with what you already hold.
//! - `rotate` rotates the black-box key **in place**, with the recorder's
//!   writer stopped (`robodr-agentd` holds the directory lock otherwise):
//!   it opens the log `DIR` of unit `--device` with the current secret key
//!   `--old-key` (records signed by keys retired earlier need
//!   `--previous-keys`, public key or keyring files), writes a
//!   `KeyRotation` record signed by the old key that names the new one
//!   (`--new-key`, an Ed25519 secret key file with another key id), and a
//!   seal under the new key (`Recorder::rotate_key`). The chain continues;
//!   nothing is archived or rewritten. Afterwards the writer must open the
//!   log with the new key **and** the old public key as a previous key
//!   (`robodr-agentd`: `blackbox.key_file` = the new key,
//!   `blackbox.previous_keys` += the old `.pub`); verifiers need both
//!   public keys (`verify --keyring old.pub --keyring new.pub`). Re-running
//!   it after a successful rotation reports "already rotated" (exit 0).
//!   `--previous-keys` files get robodr-agentd's `blackbox.previous_keys`
//!   checks (public files only, bound to `--device` if bound, owned by
//!   root or this user and not group/world-writable). The old key's
//!   export cursor, checkpoint and head mark are re-signed under the new
//!   key (a retired key vouches only for positions up to its rotation);
//!   `--tpm-sidecar FILE` (the TPM anchor's `sidecar`) re-signs the TPM
//!   anchor sidecar too, which is otherwise refused until the next mark.
//!   `--boot-id` defaults to this boot's id; `--reason` is recorded.
//! - `inspect` lists frames (seq, kind, flags, time, payload) without
//!   checking any signature: it is a viewer, not a verdict.
//! - `tpm-anchor-init` provisions the TPM 2.0 NV counter behind
//!   `robodr_blackbox::TpmNvCounterAnchor`: it defines `--index` under the
//!   owner hierarchy with `authread|authwrite|nt=counter|no_da`, size 8
//!   (`tpm2_nvdefine`), and refuses an index that already exists. The
//!   counter stays unwritten until the recorder's first mark. Default TCTI
//!   `device:/dev/tpmrm0`, tools from `/usr/bin`. Authorization values are
//!   read from files (`file:` for tpm2-tools), never from argv.
//! - `tpm-anchor-check` reads the index's public area and value and exits
//!   1 if it is not a counter.
//! - `anchor-mark` (one-way remote anchor, see
//!   `robodr_blackbox::remote_anchor`): reads `DIR/head.json`, checks it
//!   is signed by `--key` (the recorder's secret key file), and writes the
//!   signed mark of unit `--unit` (the `advance` request line) to `--out`
//!   (created new, never overwritten) or stdout, for
//!   `robodr-anchor-receiver ingest` on the far side of a diode.
//! - `export-pending` moves the black box's unexported records out of the
//!   unit **while the recorder runs** (`robodr_blackbox::outbox`): every
//!   record after the signed export cursor of log `DIR` (unit `--device`)
//!   becomes `RBBXBND1` bundles in `--out-dir` (the diode / media outbox,
//!   `rbbx-<device>-<chain>-<first>-<last>.rbbx`), each written durably
//!   before the cursor is advanced (signed with `--key`, the recorder's
//!   current secret key; records signed by keys retired by a rotation need
//!   `--previous-keys`; a `--key` that did not sign the newest record, a
//!   key retired by `rotate`, is refused before anything is written).
//!   Segments are streamed one frame at a time (memory follows
//!   `--max-bytes`, not the segment size). Each record's hash, signature
//!   and link are checked
//!   first; a bundle stops at a break. With
//!   `blackbox.retention.unexported_reserve_segments` the recorder keeps
//!   segments this has not exported. Up to `--max-bundles` (default 64)
//!   bundles of at most `--max-records` (100000) records / `--max-bytes`
//!   (64 MiB) per run. It prints one line per bundle; records lost before
//!   they were exported (a gap after the cursor) are reported and make the
//!   run exit 1 after writing what is there. Example units (not installed
//!   by the package): `packaging/systemd/blackbox-export/`
//!   (OPERATIONS 8.2).
//! - `backup` backs a unit up and restores it as OPERATIONS §14 says
//!   (`robodr_blackbox::backup`): `create` archives the §14.1 "back up"
//!   paths under `--root` (default `/`) into an `RBKUP001` archive
//!   (`--out`, created new, 0600; `-` = stdout, to pipe into the site's
//!   encryption); the keys (`etc/robodr/keys`) only with `--include-keys`.
//!   `verify` checks an archive end to end (unkeyed SHA-256: corruption,
//!   not tampering; the archive's authenticity rests on the encrypted,
//!   offline media it was kept on). `restore` verifies the whole archive
//!   first, then writes configuration (and the anchor receiver's state)
//!   under `--root`, checking each entry again against the verified pass
//!   (an archive that changed in between stops the restore, exit 1),
//!   never anything the §14.1 table says must not be restored
//!   (anti-rollback floors, replay stores, security floor, TPM-bound
//!   material, exporter sequence state: each is listed with the reason),
//!   evidence only under `--evidence-to` (never into the unit: a directory
//!   that resolves to the root or into its live trees is refused, exit 2),
//!   and the spools' `ready/` findings only with `--spool-ready` and only
//!   into an empty `ready/`. `--dry-run` reports without writing.
//!
//! Exit codes: 0 = verified intact (warnings allowed unless `--strict`),
//! 1 = verification failed, 2 = usage, I/O or key error.
//!
//! Secrets are never accepted on the command line (argv is visible to every
//! process through /proc).

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::keys::{public_key_path, KeyFile, Keyring};
use robodr_blackbox::record::KeyRef;
use robodr_blackbox::record::{scan_frames, signing_message, ScanItem};
use robodr_blackbox::remote_anchor::RemoteMark;
use robodr_blackbox::store::{CHECKPOINT_FILE, HEAD_FILE};
use robodr_blackbox::tpm_anchor::{self, parse_nv_index, NvCounter, Tpm2Tools};
use robodr_blackbox::verify::{read_segments, verify_dir, SegmentData, VerifyOptions};
use robodr_blackbox::{Bundle, Checkpoint};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  robodr-blackbox keygen     --out FILE [--alg ed25519|hmac --allow-hmac] [--key-id ID]
                             [--pub-out FILE] [--device ID]
  robodr-blackbox export-pub KEYFILE [--out FILE]
  robodr-blackbox verify     DIR --keyring FILE [--keyring FILE]... [--checkpoint FILE]
                             [--device ID] [--allow-hmac] [--allow-mixed-algorithms]
                             [--strict] [--json]
  robodr-blackbox verify     BUNDLE --keyring FILE [--keyring FILE]... [--device ID]
                             [--signing-key ID] [--allow-hmac] [--allow-mixed-algorithms]
                             [--strict] [--json]
  robodr-blackbox rotate     DIR --old-key FILE --new-key FILE --device ID
                             [--previous-keys FILE]... [--tpm-sidecar FILE]
                             [--boot-id ID] [--reason TEXT]
                             [--allow-hmac]
  robodr-blackbox inspect    DIR|SEGMENT [--json] [--limit N]
  robodr-blackbox tpm-anchor-init  --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
                             [--owner-auth-file FILE] [--index-auth-file FILE]
  robodr-blackbox tpm-anchor-check --index 0x01XXXXXX [--tcti TCTI] [--tools-dir DIR]
                             [--index-auth-file FILE]
  robodr-blackbox anchor-mark DIR --key FILE --unit ID [--out FILE] [--allow-hmac]
  robodr-blackbox export-pending DIR --key FILE --device ID --out-dir DIR
                             [--previous-keys FILE]... [--max-records N] [--max-bytes N]
                             [--max-bundles N] [--allow-hmac]
  robodr-blackbox backup create  --out FILE|- [--root DIR] [--include-keys]
  robodr-blackbox backup verify  FILE
  robodr-blackbox backup restore FILE [--root DIR] [--spool-ready]
                             [--evidence-to DIR] [--dry-run]
  robodr-blackbox --version
keygen defaults to ed25519 (secret FILE, 0600; public FILE.pub, safe to share).
--keyring accepts secret key files (0600, own user or root) and public key
files (any mode). Legacy hmac-sha256 keys are refused unless --allow-hmac.
exit: 0 intact, 1 verification failed, 2 usage/IO/key error";

const HMAC_WARNING: &str = "warning: hmac-sha256 is the legacy symmetric placeholder: every \
holder of this key can also forge evidence. Use ed25519 for production.";

/// The legacy-HMAC gate: `kf` passes if it is not HMAC, or with
/// `--allow-hmac` (then warns).
fn hmac_gate(kf: &KeyFile, shown: &str, allow_hmac: bool) -> Result<(), String> {
    kf.check_hmac_policy(allow_hmac)
        .map_err(|e| format!("{shown}: {e}"))?;
    if kf.is_symmetric() {
        eprintln!("{HMAC_WARNING} [{shown}, allowed by --allow-hmac]");
    }
    Ok(())
}

const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;
/// Largest bundle file `verify` reads.
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const PAYLOAD_PREVIEW: usize = 160;

struct Args {
    positional: Vec<String>,
    opts: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse(raw: &[String], valued: &[&str], flags: &[&str]) -> Result<Self, String> {
        let mut a = Args {
            positional: Vec::new(),
            opts: Vec::new(),
            flags: Vec::new(),
        };
        let mut it = raw.iter();
        while let Some(x) = it.next() {
            if let Some(name) = x.strip_prefix("--") {
                if valued.contains(&name) {
                    let v = it.next().ok_or(format!("--{name} needs a value"))?;
                    a.opts.push((name.to_string(), v.clone()));
                } else if flags.contains(&name) {
                    a.flags.push(name.to_string());
                } else {
                    return Err(format!("unknown option --{name}"));
                }
            } else {
                a.positional.push(x.clone());
            }
        }
        Ok(a)
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn one(&self, name: &str) -> Result<Option<&str>, String> {
        match self.all(name).as_slice() {
            [] => Ok(None),
            [v] => Ok(Some(v)),
            _ => Err(format!("--{name} given more than once")),
        }
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
    fn single_positional(&self, what: &str) -> Result<&str, String> {
        match self.positional.as_slice() {
            [p] => Ok(p),
            [] => Err(format!("missing {what}")),
            _ => Err("too many arguments".into()),
        }
    }
}

enum Fail {
    Usage(String),
    Verify,
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Usage(s)
    }
}

fn main() -> ExitCode {
    // args_os: std::env::args() panics on an argument that is not valid
    // Unicode; that is a usage error (exit 2).
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("robodr-blackbox: an argument is not valid UTF-8\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let res = match argv.first().map(String::as_str) {
        Some("keygen") => keygen(&argv[1..]),
        Some("export-pub") => export_pub(&argv[1..]),
        Some("verify") => verify(&argv[1..]),
        Some("rotate") => rotate(&argv[1..]),
        Some("inspect") => inspect(&argv[1..]),
        Some("tpm-anchor-init") => tpm_anchor_init(&argv[1..]),
        Some("tpm-anchor-check") => tpm_anchor_check(&argv[1..]),
        Some("anchor-mark") => anchor_mark(&argv[1..]),
        Some("export-pending") => export_pending(&argv[1..]),
        Some("backup") => backup(&argv[1..]),
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("-V" | "--version") if argv.len() == 1 => {
            println!(
                "{}",
                robodr_buildinfo::version_line("robodr-blackbox", env!("CARGO_PKG_VERSION"))
            );
            Ok(())
        }
        _ => Err(Fail::Usage("missing or unknown subcommand".into())),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Verify) => ExitCode::from(1),
        Err(Fail::Usage(m)) => {
            eprintln!("robodr-blackbox: {m}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn keygen(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &["out", "key-id", "alg", "pub-out", "device"],
        &["allow-hmac"],
    )?;
    if !a.positional.is_empty() {
        return Err("keygen takes no positional arguments".to_string().into());
    }
    let out = Path::new(
        a.one("out")?
            .ok_or_else(|| "--out FILE is required".to_string())?,
    );
    let alg = match a.one("alg")?.unwrap_or("ed25519") {
        "ed25519" => "ed25519",
        "hmac" | "hmac-sha256" => "hmac-sha256",
        other => return Err(format!("--alg {other:?}: expected ed25519 or hmac").into()),
    };
    if alg == "hmac-sha256" && !a.flag("allow-hmac") {
        return Err(
            "--alg hmac: legacy hmac-sha256 keys are refused by default (symmetric: \
             whoever can verify can also forge); use ed25519, or add --allow-hmac to write one \
             knowingly"
                .to_string()
                .into(),
        );
    }
    let pub_out = match (alg, a.one("pub-out")?) {
        ("ed25519", Some(p)) => Some(PathBuf::from(p)),
        ("ed25519", None) => Some(public_key_path(out)),
        (_, Some(_)) => {
            return Err("--pub-out: an hmac key has no public half"
                .to_string()
                .into())
        }
        (_, None) => None,
    };
    if let Some(p) = &pub_out {
        if p == out {
            return Err("--pub-out must differ from --out".to_string().into());
        }
        // Refuse before writing anything, so a half-made pair never exists.
        if std::fs::symlink_metadata(p).is_ok() {
            return Err(format!("{}: refusing to overwrite an existing file", p.display()).into());
        }
    }
    let device = a.one("device")?;
    let key = KeyFile::generate(alg, a.one("key-id")?)
        .and_then(|k| k.with_device_id(device))
        .map_err(|e| e.to_string())?;
    key.write_new(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    if let Some(p) = &pub_out {
        let res = key
            .to_public()
            .and_then(|pk| pk.write_new(p))
            .map_err(|e| format!("{}: {e}", p.display()));
        if let Err(e) = res {
            // Never leave a secret without its public half (and no stray
            // secret either): undo the secret file.
            let _ = std::fs::remove_file(out);
            return Err(e.into());
        }
        eprintln!(
            "wrote secret key {} (mode 0600, keep on the unit) and public key {} (safe to distribute)",
            out.display(),
            p.display()
        );
    } else {
        eprintln!("{HMAC_WARNING}");
    }
    println!("{}", key.key_id);
    Ok(())
}

fn export_pub(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["out"], &[])?;
    let src = a.single_positional("key file")?;
    let key = KeyFile::load(Path::new(src)).map_err(|e| format!("{src}: {e}"))?;
    let public = key.to_public().map_err(|e| format!("{src}: {e}"))?;
    match a.one("out")? {
        Some(out) => {
            public
                .write_new(Path::new(out))
                .map_err(|e| format!("{out}: {e}"))?;
            println!("{}", public.key_id);
        }
        None => print!("{}", public.to_json()),
    }
    Ok(())
}

fn verify(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &["keyring", "checkpoint", "device", "signing-key"],
        &["strict", "json", "allow-mixed-algorithms", "allow-hmac"],
    )?;
    let dir = PathBuf::from(a.single_positional("log directory or bundle file")?);
    let files = a.all("keyring");
    if files.is_empty() {
        return Err("--keyring FILE is required".to_string().into());
    }
    let mut ring = Keyring::new();
    ring.set_allow_mixed_algorithms(a.flag("allow-mixed-algorithms"));
    ring.set_refuse_hmac(!a.flag("allow-hmac"));
    for f in files {
        ring.load_file(Path::new(f))
            .map_err(|e| format!("{f}: {e}"))?;
    }
    let symmetric = ring.symmetric_key_ids();
    if !symmetric.is_empty() {
        eprintln!(
            "warning: symmetric (hmac-sha256) key(s) {} (allowed by --allow-hmac): anyone \
             holding them can also forge",
            symmetric.join(", ")
        );
    }
    let mut opts = VerifyOptions {
        expected_device_id: a.one("device")?.map(str::to_string),
        ..Default::default()
    };
    if let Some(p) = a.one("checkpoint")? {
        let text = read_bounded(Path::new(p), MAX_CHECKPOINT_BYTES)?;
        opts.checkpoint =
            Some(Checkpoint::from_json(&text).ok_or(format!("{p}: not a checkpoint"))?);
    }
    let report = if dir.is_file() {
        if opts.checkpoint.is_some() {
            return Err("--checkpoint applies to a log directory, not a bundle"
                .to_string()
                .into());
        }
        let bytes = read_bytes_bounded(&dir, MAX_BUNDLE_BYTES)?;
        let bundle = Bundle::from_bytes(&bytes).map_err(|e| format!("{}: {e}", dir.display()))?;
        let signing_key = match a.one("signing-key")? {
            None => None,
            Some(id) => {
                let v = ring
                    .get(id)
                    .ok_or(format!("--signing-key {id}: not in the keyring"))?;
                Some(KeyRef {
                    key_id: id.to_string(),
                    algorithm: v.algorithm().to_string(),
                })
            }
        };
        bundle.verify_with_key(
            &ring,
            None,
            opts.expected_device_id.as_deref(),
            signing_key.as_ref(),
        )
    } else {
        if a.one("signing-key")?.is_some() {
            return Err("--signing-key applies to a bundle file".to_string().into());
        }
        if !dir.is_dir() {
            return Err(format!("{}: not a directory", dir.display()).into());
        }
        verify_dir(&dir, &ring, &opts).map_err(|e| format!("{}: {e}", dir.display()))?
    };
    let ok = report.is_intact() && (!a.flag("strict") || report.is_clean());
    if a.flag("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        if let Some(id) = &report.identity {
            println!(
                "chain {} device {} key {} ({})",
                report.chain_id.as_deref().unwrap_or("?"),
                id.device_id,
                id.key_id,
                id.algorithm
            );
        }
        println!(
            "frames {} verified {} seq {:?}..={:?} last seal {:?}",
            report.frames,
            report.verified_records,
            report.first_seq,
            report.last_seq,
            report.last_seal_seq
        );
        println!("keys {}", ring.key_ids().join(", "));
        for f in &report.findings {
            println!("{f}");
        }
        println!(
            "RESULT: {}",
            if !report.is_intact() {
                "TAMPER"
            } else if report.is_clean() {
                "INTACT, CLEAN"
            } else {
                "INTACT, WITH WARNINGS"
            }
        );
    }
    if ok {
        Ok(())
    } else {
        Err(Fail::Verify)
    }
}

/// Largest number of `--previous-keys` files.
const MAX_PREVIOUS_KEY_FILES: usize = 32;

fn rotate(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &[
            "old-key",
            "new-key",
            "device",
            "previous-keys",
            "boot-id",
            "reason",
            "tpm-sidecar",
        ],
        &["allow-hmac"],
    )?;
    let dir = PathBuf::from(a.single_positional("log directory")?);
    let req = |n: &str| -> Result<String, String> {
        a.one(n)?
            .map(str::to_string)
            .ok_or_else(|| format!("--{n} is required"))
    };
    let (old_p, new_p, device) = (req("old-key")?, req("new-key")?, req("device")?);
    let allow_hmac = a.flag("allow-hmac");
    // Never start a new chain by mistake: the log must exist.
    let segments = robodr_blackbox::store::list_segments(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    if segments.is_empty() {
        return Err(format!(
            "{}: no black-box segments: nothing to rotate (a new log is simply started with the \
             new key)",
            dir.display()
        )
        .into());
    }
    let old = KeyFile::load_secret(Path::new(&old_p)).map_err(|e| format!("{old_p}: {e}"))?;
    hmac_gate(&old, &old_p, allow_hmac)?;
    let new = KeyFile::load_secret(Path::new(&new_p)).map_err(|e| format!("{new_p}: {e}"))?;
    if new.algorithm != robodr_blackbox::sign_ed25519::ED25519 {
        return Err(format!(
            "{new_p}: the new key must be ed25519 (got {}); rotating to a legacy hmac key is \
             refused",
            new.algorithm
        )
        .into());
    }
    if new.key_id == old.key_id {
        return Err(
            "--new-key has the same key id as --old-key: rotation needs a new key id \
             (robodr-blackbox keygen --key-id ...)"
                .to_string()
                .into(),
        );
    }
    let prev_files = a.all("previous-keys");
    if prev_files.len() > MAX_PREVIOUS_KEY_FILES {
        return Err(format!("at most {MAX_PREVIOUS_KEY_FILES} --previous-keys files").into());
    }
    // The checks robodr-agentd applies to blackbox.previous_keys: public
    // files only (no ed25519 secret), bound to this device if bound at all,
    // trust-anchor owner/mode, HMAC only with --allow-hmac, neither the
    // current nor the new key.
    let prev_paths: Vec<&Path> = prev_files.iter().map(Path::new).collect();
    let mut warnings = Vec::new();
    let prev = robodr_blackbox::keys::load_previous_keys(
        "--previous-keys",
        &prev_paths,
        &device,
        &[
            (
                old.key_id.as_str(),
                "the --old-key (the key the log is signed with now)",
            ),
            (
                new.key_id.as_str(),
                "the new key id: a retired key id is never reused",
            ),
        ],
        allow_hmac,
        &mut warnings,
    )?;
    for w in warnings {
        eprintln!("robodr-blackbox: warning: {w}");
    }
    let tpm_sidecar = a.one("tpm-sidecar")?.map(PathBuf::from);
    if let Some(p) = &tpm_sidecar {
        if !p.is_absolute() {
            return Err(format!("--tpm-sidecar {}: must be an absolute path", p.display()).into());
        }
    }
    let boot_id = match a.one("boot-id")? {
        Some(b) => b.to_string(),
        None => std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown-boot".into()),
    };
    let reason = a.one("reason")?.unwrap_or("robodr-blackbox rotate");
    let cfg = robodr_blackbox::RecorderConfig::new(&dir, &device, &boot_id);
    let old_signer = old.signer().map_err(|e| format!("{old_p}: {e}"))?;
    let new_signer = new.signer().map_err(|e| format!("{new_p}: {e}"))?;
    let prev_box: Option<Box<dyn robodr_blackbox::Verifier>> =
        (!prev.is_empty()).then(|| Box::new(prev.clone()) as Box<dyn robodr_blackbox::Verifier>);
    let clock = robodr_blackbox::SystemClock::new(robodr_blackbox::TimeSource::Unknown);
    let mut r = match robodr_blackbox::Recorder::open_with_keys(
        cfg,
        old_signer,
        None,
        prev_box,
        Box::new(clock),
    ) {
        Ok(r) => r,
        Err(robodr_blackbox::Error::KeyMismatch { log_key_id, .. })
            if log_key_id == format!("{}/{}", new.algorithm, new.key_id) =>
        {
            // A re-run after a crash between the rotation and the sidecar.
            resign_tpm_sidecar(tpm_sidecar.as_deref(), &old, &new, &old_p, &new_p)?;
            eprintln!(
                "robodr-blackbox: {}: already rotated to {} (nothing written to the log)",
                dir.display(),
                new.key_id
            );
            println!("{}", new.key_id);
            return Ok(());
        }
        Err(e @ robodr_blackbox::Error::KeyMismatch { .. }) => {
            return Err(format!(
                "{}: {e}: --old-key must be the key the log is signed with now",
                dir.display()
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "{}: {e} (stop the writer first; keys retired by an earlier rotation go in \
                 --previous-keys)",
                dir.display()
            )
            .into())
        }
    };
    let cp = r
        .rotate_key(new_signer, None, reason)
        .map_err(|e| format!("{}: rotation failed: {e}", dir.display()))?;
    r.close()
        .map_err(|e| format!("{}: closing after the rotation: {e}", dir.display()))?;
    resign_tpm_sidecar(tpm_sidecar.as_deref(), &old, &new, &old_p, &new_p)?;
    eprintln!(
        "robodr-blackbox: {}: rotated {} -> {} (seal seq {}); the writer now needs the new key \
         and {}'s public key as a previous key (robodr-agentd: blackbox.previous_keys); \
         verifiers need both public keys",
        dir.display(),
        old.key_id,
        new.key_id,
        cp.seq,
        old.key_id
    );
    println!("{}", new.key_id);
    Ok(())
}

/// `rotate --tpm-sidecar`: re-sign the TPM anchor's sidecar under the new
/// key (a sidecar under a retired key is never trusted).
fn resign_tpm_sidecar(
    path: Option<&Path>,
    old: &KeyFile,
    new: &KeyFile,
    old_p: &str,
    new_p: &str,
) -> Result<(), Fail> {
    let Some(path) = path else {
        return Ok(());
    };
    let o = old.signer().map_err(|e| format!("{old_p}: {e}"))?;
    let n = new.signer().map_err(|e| format!("{new_p}: {e}"))?;
    match robodr_blackbox::tpm_anchor::resign_sidecar(path, &*o, &*n) {
        Ok(true) => eprintln!(
            "robodr-blackbox: {}: TPM anchor sidecar signed by {}",
            path.display(),
            new.key_id
        ),
        Ok(false) => eprintln!(
            "robodr-blackbox: {}: no TPM anchor sidecar (nothing to re-sign)",
            path.display()
        ),
        Err(e) => return Err(format!("--tpm-sidecar {}: {e}", path.display()).into()),
    }
    Ok(())
}

/// The counter named by `--index`, reached with `--tcti` / `--tools-dir`.
fn tpm_counter(a: &Args) -> Result<NvCounter, String> {
    if !a.positional.is_empty() {
        return Err("tpm-anchor commands take no positional arguments".into());
    }
    let index = parse_nv_index(a.one("index")?.ok_or("--index 0x01XXXXXX is required")?)?;
    let tools = Tpm2Tools::new(
        a.one("tools-dir")?.unwrap_or(tpm_anchor::DEFAULT_TOOLS_DIR),
        a.one("tcti")?.unwrap_or(tpm_anchor::DEFAULT_TCTI),
        Duration::from_secs(30),
    )?;
    let auth = abs_file(a.one("index-auth-file")?, "--index-auth-file")?;
    Ok(NvCounter::new(index, auth, Box::new(tools)))
}

fn abs_file(v: Option<&str>, what: &str) -> Result<Option<PathBuf>, String> {
    match v.map(PathBuf::from) {
        Some(p) if !p.is_absolute() => Err(format!("{what} must be an absolute path")),
        Some(p) if !p.is_file() => Err(format!("{what} {}: not a file", p.display())),
        other => Ok(other),
    }
}

fn tpm_anchor_init(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(
        raw,
        &[
            "index",
            "tcti",
            "tools-dir",
            "owner-auth-file",
            "index-auth-file",
        ],
        &[],
    )?;
    let c = tpm_counter(&a)?;
    let owner = abs_file(a.one("owner-auth-file")?, "--owner-auth-file")?;
    let index_auth = abs_file(a.one("index-auth-file")?, "--index-auth-file")?;
    let idx = tpm_anchor::format_nv_index(c.index());
    if let Ok(p) = c.read_public() {
        return Err(format!(
            "NV index {idx} is already defined (attributes {:#010x}, counter: {}); refusing to \
             touch it (undefine it first with tpm2_nvundefine if it is really unused)",
            p.attributes,
            p.is_counter()
        )
        .into());
    }
    c.define(owner.as_deref(), index_auth.as_deref())?;
    let p = c.check_counter()?;
    eprintln!(
        "defined NV counter {idx} ({}, attributes {:#010x}); it stays unwritten until the \
         recorder's first mark",
        tpm_anchor::PROVISION_ATTRIBUTES,
        p.attributes
    );
    println!("{idx}");
    Ok(())
}

fn tpm_anchor_check(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["index", "tcti", "tools-dir", "index-auth-file"], &[])?;
    let c = tpm_counter(&a)?;
    let idx = tpm_anchor::format_nv_index(c.index());
    let p = c.read_public()?;
    if !p.is_counter() || p.size != 8 {
        eprintln!(
            "NV index {idx} is not a counter (attributes {:#010x}, size {})",
            p.attributes, p.size
        );
        return Err(Fail::Verify);
    }
    let value = if p.written() {
        c.read()?.to_string()
    } else {
        "unwritten".to_string()
    };
    println!(
        "{}",
        serde_json::json!({
            "nv_index": idx,
            "attributes": format!("{:#010x}", p.attributes),
            "counter": true,
            "orderly": p.attributes & tpm_anchor::attr::ORDERLY != 0,
            "written": p.written(),
            "value": value,
        })
    );
    Ok(())
}

fn anchor_mark(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["key", "unit", "out"], &["allow-hmac"])?;
    let dir = Path::new(a.single_positional("DIR")?);
    let key = a
        .one("key")?
        .ok_or_else(|| "--key FILE is required".to_string())?;
    let unit = a
        .one("unit")?
        .ok_or_else(|| "--unit ID is required".to_string())?;
    let k = KeyFile::load_secret(Path::new(key)).map_err(|e| format!("{key}: {e}"))?;
    hmac_gate(&k, key, a.flag("allow-hmac"))?;
    let signer = k.signer().map_err(|e| format!("{key}: {e}"))?;
    let text = read_bounded(&dir.join(HEAD_FILE), MAX_CHECKPOINT_BYTES)?;
    let cp = Checkpoint::from_json(&text)
        .ok_or_else(|| format!("{}: unparseable head mark", dir.join(HEAD_FILE).display()))?;
    if signer.verify_own(&signing_message(&cp.hash), &cp.sig) != Some(true) {
        return Err(format!(
            "{}: not signed by {key} (another unit's directory or key?)",
            dir.join(HEAD_FILE).display()
        )
        .into());
    }
    let m = RemoteMark::sign(unit, &cp, &*signer)?;
    let mut line = m.to_request_line();
    line.push('\n');
    match a.one("out")? {
        None => print!("{line}"),
        Some(out) => {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o644);
            }
            let mut f = o.open(out).map_err(|e| format!("{out}: {e}"))?;
            std::io::Write::write_all(&mut f, line.as_bytes())
                .and_then(|()| f.sync_all())
                .map_err(|e| format!("{out}: {e}"))?;
            eprintln!(
                "robodr-blackbox: mark of unit {unit} seq {} written to {out}",
                m.seq
            );
        }
    }
    Ok(())
}

fn positive(a: &Args, name: &str, default: u64) -> Result<u64, String> {
    match a.one(name)? {
        None => Ok(default),
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!("--{name} must be a positive integer")),
        },
    }
}

fn export_pending(raw: &[String]) -> Result<(), Fail> {
    use robodr_blackbox::outbox::{export_pending_to, PendingOptions};
    let a = Args::parse(
        raw,
        &[
            "key",
            "device",
            "out-dir",
            "previous-keys",
            "max-records",
            "max-bytes",
            "max-bundles",
        ],
        &["allow-hmac"],
    )?;
    let dir = PathBuf::from(a.single_positional("log directory")?);
    let req = |n: &str| -> Result<String, String> {
        a.one(n)?
            .map(str::to_string)
            .ok_or_else(|| format!("--{n} is required"))
    };
    let (key_p, device, out) = (req("key")?, req("device")?, req("out-dir")?);
    let out = PathBuf::from(out);
    if !out.is_dir() {
        return Err(format!("--out-dir {}: not a directory", out.display()).into());
    }
    let allow_hmac = a.flag("allow-hmac");
    let key = KeyFile::load_secret(Path::new(&key_p)).map_err(|e| format!("{key_p}: {e}"))?;
    hmac_gate(&key, &key_p, allow_hmac)?;
    let prev_files = a.all("previous-keys");
    if prev_files.len() > MAX_PREVIOUS_KEY_FILES {
        return Err(format!("at most {MAX_PREVIOUS_KEY_FILES} --previous-keys files").into());
    }
    let prev_paths: Vec<&Path> = prev_files.iter().map(Path::new).collect();
    let mut warnings = Vec::new();
    let prev = robodr_blackbox::keys::load_previous_keys(
        "--previous-keys",
        &prev_paths,
        &device,
        &[(
            key.key_id.as_str(),
            "the --key (the key the log is signed with now)",
        )],
        allow_hmac,
        &mut warnings,
    )?;
    for w in warnings {
        eprintln!("robodr-blackbox: warning: {w}");
    }
    let signer = key.signer().map_err(|e| format!("{key_p}: {e}"))?;
    let opts = PendingOptions {
        max_records: usize::try_from(positive(&a, "max-records", 100_000)?)
            .map_err(|_| "--max-records is too large".to_string())?,
        max_bytes: positive(&a, "max-bytes", 64 * 1024 * 1024)?,
    };
    let max_bundles = positive(&a, "max-bundles", 64)?;
    let authentic = |m: &[u8], s: &[u8]| {
        signer.verify_own(m, s) == Some(true)
            || (!prev.is_empty() && robodr_blackbox::Verifier::verify_any(&prev, m, s))
    };
    let mut lost = false;
    let mut written = 0u64;
    for _ in 0..max_bundles {
        let res = export_pending_to(&dir, &out, &*signer, &authentic, opts, Some(&device))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let Some((p, path)) = res else {
            break;
        };
        written += 1;
        if let Some(why) = &p.cursor_rejected {
            eprintln!(
                "robodr-blackbox: warning: export cursor ignored ({why}); exported from the \
                 oldest retained record"
            );
        }
        if let Some([lo, hi]) = p.gap {
            lost = true;
            eprintln!(
                "robodr-blackbox: EVIDENCE LOST BEFORE EXPORT: records {lo}..={hi} after the \
                 export cursor are no longer in the black box (dropped by retention or \
                 quarantined); the receiver will report the gap"
            );
        }
        println!(
            "exported seq {}..={} ({} records) to {}",
            p.first_seq,
            p.last_seq,
            p.records,
            path.display()
        );
        if !p.more {
            break;
        }
    }
    if written == 0 {
        println!("nothing pending");
    }
    if lost {
        return Err(Fail::Verify);
    }
    Ok(())
}

fn backup(raw: &[String]) -> Result<(), Fail> {
    use robodr_blackbox::backup;
    let (sub, rest) = raw
        .split_first()
        .ok_or_else(|| "backup needs create, verify or restore".to_string())?;
    match sub.as_str() {
        "create" => {
            let a = Args::parse(rest, &["out", "root"], &["include-keys"])?;
            if !a.positional.is_empty() {
                return Err("backup create takes no positional argument"
                    .to_string()
                    .into());
            }
            let out = a
                .one("out")?
                .ok_or_else(|| "--out FILE (or -) is required".to_string())?;
            let root = PathBuf::from(a.one("root")?.unwrap_or("/"));
            let include_keys = a.flag("include-keys");
            let rep = if out == "-" {
                let stdout = std::io::stdout();
                let mut w = std::io::BufWriter::new(stdout.lock());
                backup::create(&root, &mut w, include_keys).map_err(|e| format!("backup: {e}"))?
            } else {
                let mut o = std::fs::OpenOptions::new();
                o.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    o.mode(0o600);
                }
                let f = o.open(out).map_err(|e| format!("{out}: {e}"))?;
                let mut w = std::io::BufWriter::new(f);
                let rep = backup::create(&root, &mut w, include_keys)
                    .map_err(|e| format!("backup: {e}"))?;
                let f = w.into_inner().map_err(|e| format!("{out}: {e}"))?;
                f.sync_all().map_err(|e| format!("{out}: {e}"))?;
                rep
            };
            for (p, why) in &rep.skipped {
                eprintln!("robodr-blackbox: not archived: {p}: {why}");
            }
            eprintln!(
                "robodr-blackbox: backup: {} files, {} directories, {} bytes{}",
                rep.files,
                rep.dirs,
                rep.bytes,
                if include_keys {
                    " (holds private keys: encrypt it before it leaves the unit, OPERATIONS 14.2)"
                } else {
                    ""
                }
            );
            Ok(())
        }
        "verify" => {
            let a = Args::parse(rest, &[], &[])?;
            let p = a.single_positional("archive")?;
            let f = std::fs::File::open(p).map_err(|e| format!("{p}: {e}"))?;
            match backup::verify(&mut std::io::BufReader::new(f)) {
                Ok(entries) => {
                    println!("{p}: intact, {} entries", entries.len());
                    Ok(())
                }
                Err(e) => {
                    eprintln!("robodr-blackbox: {p}: {e}");
                    Err(Fail::Verify)
                }
            }
        }
        "restore" => {
            let a = Args::parse(rest, &["root", "evidence-to"], &["spool-ready", "dry-run"])?;
            let p = PathBuf::from(a.single_positional("archive")?);
            let root = PathBuf::from(a.one("root")?.unwrap_or("/"));
            let opts = backup::RestoreOptions {
                spool_ready: a.flag("spool-ready"),
                evidence_to: a.one("evidence-to")?.map(PathBuf::from),
                dry_run: a.flag("dry-run"),
            };
            // `--evidence-to` inside the unit's live state (however it is
            // spelled) is refused by `backup::restore` before anything is
            // read: a usage error (exit 2).
            let rep = match backup::restore(&p, &root, &opts) {
                Ok(r) => r,
                Err(e)
                    if e.get_ref()
                        .is_some_and(|x| x.is::<backup::ArchiveChanged>()) =>
                {
                    eprintln!(
                        "robodr-blackbox: {}: {e}; entries before it were written, each \
                         checked against the verified archive; restore again from a copy \
                         nobody else can write",
                        p.display()
                    );
                    return Err(Fail::Verify);
                }
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    eprintln!(
                        "robodr-blackbox: {}: {e}; nothing was restored",
                        p.display()
                    );
                    return Err(Fail::Verify);
                }
                Err(e) => return Err(format!("restore: {e}").into()),
            };
            let verb = if opts.dry_run {
                "would restore"
            } else {
                "restored"
            };
            for x in &rep.restored {
                println!("{verb}: {x}");
            }
            for x in &rep.evidence {
                println!("evidence: {x}");
            }
            for (x, why) in &rep.refused {
                println!("not restored: {x}: {why}");
            }
            eprintln!(
                "robodr-blackbox: {verb} {} entries, {} evidence entries, {} not restored. Next \
                 (OPERATIONS 14.3): systemd-tmpfiles --create; re-create, never copy, the \
                 monotonic state (seal provisioning, enrolment, delivery anchor, depot); \
                 re-install the current signed profile; then start the services",
                rep.restored.len(),
                rep.evidence.len(),
                rep.refused.len()
            );
            Ok(())
        }
        other => Err(format!("unknown backup subcommand {other:?}").into()),
    }
}

fn read_bytes_bounded(p: &Path, max: u64) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut b = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if b.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", p.display()));
    }
    Ok(b)
}

fn read_bounded(p: &Path, max: u64) -> Result<String, String> {
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut s = String::new();
    f.take(max + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if s.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", p.display()));
    }
    Ok(s)
}

fn inspect(raw: &[String]) -> Result<(), Fail> {
    let a = Args::parse(raw, &["limit"], &["json"])?;
    let path = PathBuf::from(a.single_positional("directory or segment")?);
    let limit = match a.one("limit")? {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| format!("bad --limit {v:?}"))?,
        None => usize::MAX,
    };
    let segments = if path.is_dir() {
        read_segments(&path).map_err(|e| format!("{}: {e}", path.display()))?
    } else {
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        vec![SegmentData {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            bytes,
        }]
    };
    let json = a.flag("json");
    let mut rows = Vec::new();
    let mut shown = 0usize;
    'outer: for seg in &segments {
        let scan = scan_frames(&seg.bytes);
        for it in scan.items {
            if shown == limit {
                break 'outer;
            }
            shown += 1;
            let row = match it {
                ScanItem::Record(sr) => {
                    let r = sr.record;
                    let preview: String = String::from_utf8_lossy(&r.payload)
                        .chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .take(PAYLOAD_PREVIEW)
                        .collect();
                    serde_json::json!({
                        "segment": seg.name, "offset": sr.offset, "seq": r.seq,
                        "kind": r.kind, "critical": r.critical,
                        "wall_ns": r.time.wall_ns, "time_source": format!("{:?}", r.time.source),
                        "hash": to_hex(&r.hash), "hash_ok": r.compute_hash() == r.hash,
                        "payload": preview,
                    })
                }
                ScanItem::Malformed {
                    offset,
                    len,
                    reason,
                } => serde_json::json!({
                    "segment": seg.name, "offset": offset, "malformed": reason, "len": len,
                }),
            };
            if json {
                rows.push(row);
            } else {
                print_row(&row);
            }
        }
        if let Some(t) = scan.tail {
            let row = serde_json::json!({
                "segment": seg.name, "offset": t.offset, "tail": format!("{:?}", t.kind), "len": t.len,
            });
            if json {
                rows.push(row);
            } else {
                print_row(&row);
            }
        }
    }
    let checkpoint = if path.is_dir() {
        read_bounded(&path.join(CHECKPOINT_FILE), MAX_CHECKPOINT_BYTES).ok()
    } else {
        None
    };
    if json {
        let out = serde_json::json!({
            "signatures_checked": false,
            "segments": segments.iter().map(|s| &s.name).collect::<Vec<_>>(),
            "frames": rows,
            "checkpoint": checkpoint.as_deref().and_then(Checkpoint::from_json).map(|c| serde_json::json!({
                "seq": c.seq, "hash": to_hex(&c.hash), "key_id": c.key_id,
            })),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        if let Some(c) = checkpoint.as_deref().and_then(Checkpoint::from_json) {
            println!(
                "{CHECKPOINT_FILE}: seq {} hash {} key {}",
                c.seq,
                to_hex(&c.hash),
                c.key_id
            );
        }
        println!("(signatures not checked; use `verify` for a verdict)");
    }
    Ok(())
}

fn print_row(v: &serde_json::Value) {
    let g = |k: &str| v.get(k).map(|x| x.to_string()).unwrap_or_default();
    if v.get("seq").is_some() {
        println!(
            "{}+{} seq {} {} {}{} wall_ns {} {} {}",
            g("segment").trim_matches('"'),
            g("offset"),
            g("seq"),
            g("kind").trim_matches('"'),
            if v["critical"] == true {
                "critical "
            } else {
                ""
            },
            if v["hash_ok"] == true {
                ""
            } else {
                "HASH-MISMATCH "
            },
            g("wall_ns"),
            g("time_source").trim_matches('"'),
            v["payload"].as_str().unwrap_or("")
        );
    } else {
        println!("{v}");
    }
}
