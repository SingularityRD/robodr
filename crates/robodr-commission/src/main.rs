//! `robodr-commission`: observe-mode commissioning CLI.
//!
//! Exit codes: 0 success / clean; 1 negative result (deviations found,
//! profiles differ, lock refused); 2 usage, input or I/O error.
//! Argument parsing is std-only by design (no third-party crates on the
//! robot's build).
//!
//! File handling: every output goes through
//! [`write_file_atomic`](robodr_commission::write_file_atomic) (temp file +
//! fsync + atomic publish, never through a symlink, never clobbering an
//! existing file unless `--force`); the outputs of one command must be
//! distinct from each other and from its inputs. Profiles are loaded
//! strictly (regular file, size cap, all keys, no unknown or duplicate keys,
//! sealed if locked). A failed `learn` writes nothing: every output path is
//! checked before the inputs are read, and the draft, sign-off and report
//! are published together by
//! [`write_files_atomic`](robodr_commission::write_files_atomic) (all temps
//! first; a failed publish rolls back what was already published).
//!
//! Signing: `lock --sign-key` (and `sign`, `migrate-legacy`) write the
//! detached Ed25519 signature `<out>.sig` over the exact sealed bytes, as a
//! unit with the profile. `verify-profile` runs the same trust check the
//! loaders run (see `robodr_commission::trust`). Signing keys are read only
//! from mode-0600 key files, never from the command line.

use robodr_blackbox::keys::public_key_path;
use robodr_commission::input::{self, InputSpec};
use robodr_commission::profile_file::{check_destination, read_regular_file, MAX_PROFILE_BYTES};
use robodr_commission::trust::{
    evaluate_profile_trust, file_digest, load_revocation_list, load_signing_key, load_state,
    load_trust_keys, load_trust_roots, new_signing_key, sig_path_for, trust_file_text,
    trust_keys_text, trust_roots_text, validate_rollback_flag, verify_profile_file,
    verifying_keys_from_public_files, ProfileSignature, RevocationList, RevocationPolicy, SigKind,
    TrustInputs, TrustPolicy,
};
use robodr_commission::{
    diff, lock_draft_text_with_caps, merge_profiles_with_caps, parse_profile_text, sealed_text,
    to_json, write_files_atomic, Checker, HardCaps, LearnConfig, Learner, Signoff,
};
use robodr_events::profile::{Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
robodr-commission: learn, review, lock and verify a RoboDR model profile

USAGE:
  robodr-commission learn (--events <run.jsonl> | --pcap <run.pcap[ng]>) [...]
                          [--model NAME] [--margin 1.1] [--min-samples 30]
                          [--ceiling-linear M_PER_S] [--ceiling-joint RAD_PER_S]
                          [--hard-cap-linear 10] [--hard-cap-joint 10]
                          [--min-announcements 2] [--min-duration SECS]
                          [--outlier-ratio 3]
                          [--accept-participant GUID]... [--motion-topic /T]...
                          [--learn-readers]
                          --out profile.json [--signoff signoff.json]
                          [--report report.json] [--quiet] [--force]
  robodr-commission lock    --in profile.json --signoff signoff.json --out locked.json
                          (--parent previous-locked.json | --platform P --profile-version N)
                          [--platform P] [--unit-id U] [--profile-version N]
                          [--sign-key signing.key] [--trusted-keys trust.json]
                          [--locked-at UNIX_SECS]
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]
  robodr-commission sign    --profile locked.json --sign-key signing.key [--force]
  robodr-commission verify-profile --profile locked.json --trusted-keys trust.json
                          [--expect-platform P] [--expect-unit U]
                          [--state profile-state.json] [--allow-rollback sha256:HEX]
                          [--trust-roots roots.json [--revocations revocations.json
                           [--revocations-required]]] [--json]
  robodr-commission keygen  --out signing.key --trust-out trust.json [--key-id ID] [--roots]
  robodr-commission trust-keys --out trust.json --pub KEY.pub [--pub KEY2.pub]... [--force]
                          [--roots | [--min-profile-version N] [--sign-key ROOT.key]]
  robodr-commission revoke  --sign-key ROOT.key --out revocations.json
                          [--digest sha256:HEX]... [--revoke-profile FILE]... [--key-id ID]...
                          [--base previous.json --trust-roots roots.json]
                          [--serial N] [--issued-at UNIX_SECS] [--force]
  robodr-commission verify-revocations --list revocations.json --trust-roots roots.json
                          [--state profile-state.json] [--json]
  robodr-commission migrate-legacy --in legacy-locked.json --out locked.json
                          --platform P --profile-version N --operator NAME
                          --sign-key signing.key [--unit-id U] [--locked-at UNIX_SECS]
                          [--force]
  robodr-commission signoff --in profile.json --out signoff.json [--force]
  robodr-commission diff    <old.json> <new.json> [--json]
  robodr-commission check   --profile locked.json (--events <f> | --pcap <f>) [...] [--json]
  robodr-commission merge   --out merged.json <a.json> <b.json> [...]
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]

  --events: JSON Lines of RobotEvent. --pcap: pcap or pcapng capture of the
  robot bus (discovery only: participants, writers, readers). Both repeat and
  mix; every file is one run.
  --learn-readers: also learn reader_topics, which turns reader-topic
  enforcement on (off by default: a policy choice for the OEM).
  Anti-poisoning: participants announced fewer than --min-announcements
  times (or, in captures, seen for less than --min-duration seconds) are
  quarantined: not learned, nor their endpoints or motion samples. Use
  --accept-participant to override (it becomes a sign-off item). No
  envelope exceeds --hard-cap-linear / --hard-cap-joint, and lock and merge
  refuse any bound above them (pass the same values used for learn). A
  dimension never observed on a channel is bounded at its ceiling or 0
  (deny), never left unlimited. --outlier-ratio: max > ratio x p99 on an
  envelope needs sign-off. Endpoints announced under another participant's
  GUID, or from an IP that is not one of the owner's commissioned IPs, are
  not learned (sign-off item endpoint_sender_mismatch).
  learn writes a sign-off list (default <out>.signoff.json); lock refuses
  until a named \"operator\" has set \"confirmed\": true on every item.
  signoff builds a conservative list for an edited or merged draft.
  lock stamps metadata (schema/profile version, platform, unit, locked_by =
  sign-off operator, locked_at, parent digest): with --parent the version
  defaults to the parent's + 1 and must be higher, platform/unit default to
  the parent's, and the parent's file digest is recorded (rollback lineage).
  --sign-key writes <out>.sig (Ed25519 over the exact sealed bytes) with
  the profile; loaders refuse a locked profile without a valid signature
  from a trusted key. keygen makes an Ed25519 key file (mode 0600), its
  public key file <out>.pub and a trust file holding the public key. Key
  files are robodr-blackbox's (robodr-blackbox-key/v2): a key from
  `robodr-blackbox keygen` signs profiles too. trust-keys builds a trust
  file from Ed25519 .pub files (secret key files are refused). verify-profile is read-only (exit 0
  trusted, 1 refused).
  Trust roots (keygen/trust-keys --roots: robodr-trust-roots/v1) sign the
  revocation list and a trust file's min_profile_version; they must differ
  from every profile signing key. trust-keys --min-profile-version N
  --sign-key ROOT.key writes trust.json plus trust.json.sig (a floor no
  loader accepts unsigned, not overridable by allow_rollback). revoke signs
  a robodr-profile-revocations/v1 list of revoked profile digests and
  signing key ids; --base carries over a previous list (verified under
  --trust-roots) and the serial defaults to its serial + 1 (else 1); a
  loader refuses a list older than the last accepted one.
  verify-revocations checks a list (exit 0 valid and not older than
  --state, 1 refused). migrate-legacy re-issues a locked profile from
  before metadata existed (content unchanged, its digest recorded as
  parent).
  Outputs never overwrite an existing file or follow a symlink unless
  --force (symlinks are refused even then).

EXIT: 0 ok/clean, 1 deviations / differences / lock refused, 2 error.
";

/// Max size of a sign-off file we are willing to load.
const MAX_SIGNOFF_BYTES: u64 = 16 << 20;

struct Args {
    opts: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
    positionals: Vec<String>,
}

impl Args {
    fn parse(argv: &[String], valued: &[&str], switches: &[&str]) -> Result<Self, String> {
        let mut a = Args {
            opts: BTreeMap::new(),
            switches: Vec::new(),
            positionals: Vec::new(),
        };
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            i += 1;
            if arg == "--" {
                a.positionals.extend(argv[i..].iter().cloned());
                break;
            }
            let Some(name) = arg.strip_prefix("--") else {
                a.positionals.push(arg.clone());
                continue;
            };
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };
            if valued.contains(&name) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        let v = argv
                            .get(i)
                            .ok_or_else(|| format!("--{name} needs a value"))?;
                        i += 1;
                        v.clone()
                    }
                };
                a.opts.entry(name.to_string()).or_default().push(v);
            } else if switches.contains(&name) && inline.is_none() {
                a.switches.push(name.to_string());
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(a)
    }

    fn one(&self, name: &str) -> Result<Option<&str>, String> {
        match self.opts.get(name).map(Vec::as_slice) {
            None | Some([]) => Ok(None),
            Some([v]) => Ok(Some(v.as_str())),
            Some(_) => Err(format!("--{name} given more than once")),
        }
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.one(name)?
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn all(&self, name: &str) -> &[String] {
        self.opts.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    fn f64_opt(&self, name: &str) -> Result<Option<f64>, String> {
        self.one(name)?
            .map(|v| {
                v.parse::<f64>()
                    .ok()
                    .filter(|x| x.is_finite())
                    .ok_or_else(|| format!("--{name}: {v:?} is not a finite number"))
            })
            .transpose()
    }

    fn u64_opt(&self, name: &str) -> Result<Option<u64>, String> {
        self.one(name)?
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| format!("--{name}: {v:?} is not a non-negative integer"))
            })
            .transpose()
    }

    fn inputs(&self) -> Result<Vec<InputSpec>, String> {
        let mut v: Vec<InputSpec> = self
            .all("events")
            .iter()
            .map(|p| InputSpec::Jsonl(PathBuf::from(p)))
            .collect();
        v.extend(
            self.all("pcap")
                .iter()
                .map(|p| InputSpec::Pcap(PathBuf::from(p))),
        );
        if v.is_empty() {
            return Err(
                "at least one --events <file.jsonl> or --pcap <file.pcap> is required".into(),
            );
        }
        Ok(v)
    }
}

enum Failure {
    /// Negative result already reported (exit 1).
    Negative,
    /// Error (exit 2).
    Error(String),
}

impl From<String> for Failure {
    fn from(s: String) -> Self {
        Failure::Error(s)
    }
}

type Outcome = Result<(), Failure>;

fn main() -> ExitCode {
    // args_os: a non-UTF-8 argument is a usage error, not a panic.
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(a) => {
            eprintln!("robodr-commission: error: argument {a:?} is not valid UTF-8");
            return ExitCode::from(2);
        }
    };
    let Some((cmd, rest)) = argv.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match cmd.as_str() {
        "learn" => cmd_learn(rest),
        "lock" => cmd_lock(rest),
        "sign" => cmd_sign(rest),
        "verify-profile" => cmd_verify_profile(rest),
        "keygen" => cmd_keygen(rest),
        "trust-keys" => cmd_trust_keys(rest),
        "revoke" => cmd_revoke(rest),
        "verify-revocations" => cmd_verify_revocations(rest),
        "migrate-legacy" => cmd_migrate_legacy(rest),
        "diff" => cmd_diff(rest),
        "check" => cmd_check(rest),
        "merge" => cmd_merge(rest),
        "signoff" => cmd_signoff(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        "--version" | "version" => {
            println!("robodr-commission {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(Failure::Error(format!(
            "unknown subcommand {other:?}\n\n{USAGE}"
        ))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Negative) => ExitCode::from(1),
        Err(Failure::Error(e)) => {
            eprintln!("robodr-commission: error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Atomic, symlink-refusing, no-clobber (unless `force`) write of one or
/// more files as a unit (see `write_files_atomic`).
fn write_files(files: &[(&str, &str)], force: bool) -> Result<(), String> {
    let v: Vec<(&Path, &[u8])> = files
        .iter()
        .map(|(p, c)| (Path::new(*p), c.as_bytes()))
        .collect();
    write_files_atomic(&v, force).map_err(|e| e.to_string())
}

fn write_file(path: &str, contents: &str, force: bool) -> Result<(), String> {
    write_files(&[(path, contents)], force)
}

/// Fail early (before reading inputs) if an output could not be written.
fn precheck_outputs(paths: &[&str], force: bool) -> Result<(), String> {
    for p in paths {
        check_destination(Path::new(p), force).map_err(|e| format!("{p}: {e}"))?;
    }
    Ok(())
}

/// `--hard-cap-linear` / `--hard-cap-joint` (defaults: learn's defaults).
fn hard_caps(a: &Args) -> Result<HardCaps, String> {
    let mut caps = HardCaps::default();
    for (name, slot) in [
        ("hard-cap-linear", &mut caps.linear),
        ("hard-cap-joint", &mut caps.joint),
    ] {
        if let Some(v) = a.f64_opt(name)? {
            if v <= 0.0 {
                return Err(format!("--{name}: {v} must be > 0"));
            }
            *slot = v;
        }
    }
    Ok(caps)
}

/// Identity of a path for "same file" checks: the canonical path of an
/// existing file, else the canonical parent joined with the file name.
fn path_key(p: &str) -> PathBuf {
    let path = Path::new(p);
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    match (path.parent(), path.file_name()) {
        (Some(d), Some(n)) => {
            let d = if d.as_os_str().is_empty() {
                Path::new(".")
            } else {
                d
            };
            std::fs::canonicalize(d)
                .map(|d| d.join(n))
                .unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// Refuse a command whose outputs collide with each other or with an input
/// (e.g. `--out` naming the capture being learned).
fn distinct_paths(outputs: &[&str], inputs: &[&str]) -> Result<(), String> {
    let mut seen: BTreeMap<PathBuf, &str> = BTreeMap::new();
    for p in inputs {
        seen.insert(path_key(p), p);
    }
    for o in outputs {
        if let Some(prev) = seen.insert(path_key(o), o) {
            return Err(format!(
                "output {o:?} is the same file as {prev:?}; choose distinct paths"
            ));
        }
    }
    Ok(())
}

fn read_text(path: &str, max: u64) -> Result<String, String> {
    read_regular_file(Path::new(path), max).map_err(|e| format!("{path}: {e}"))
}

/// Strictly load a profile file (see `profile_file::parse_profile_text`).
fn load_profile(path: &str) -> Result<Profile, String> {
    let text = read_text(path, MAX_PROFILE_BYTES)?;
    parse_profile_text(&text).map_err(|e| format!("{path}: {e}"))
}

fn load_signoff(path: &str) -> Result<Signoff, String> {
    let text = read_text(path, MAX_SIGNOFF_BYTES)?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: not a sign-off file: {e}"))
}

/// Load a profile that is about to be enforced (by `check`): it must pass
/// `Profile::validate`, as the sensor requires at load time.
fn load_valid_profile(path: &str) -> Result<Profile, String> {
    let p = load_profile(path)?;
    if let Err(errs) = p.validate() {
        let list: Vec<String> = errs.iter().map(|e| format!("  - {e}")).collect();
        return Err(format!(
            "{path}: profile fails validation:\n{}",
            list.join("\n")
        ));
    }
    Ok(p)
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, String> {
    to_json(v).map_err(|e| format!("serialise: {e}"))
}

fn cmd_learn(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "events",
            "pcap",
            "margin",
            "ceiling-linear",
            "ceiling-joint",
            "model",
            "min-samples",
            "out",
            "report",
            "signoff",
            "hard-cap-linear",
            "hard-cap-joint",
            "min-announcements",
            "min-duration",
            "accept-participant",
            "motion-topic",
            "outlier-ratio",
        ],
        &["quiet", "learn-readers", "force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let mut cfg = LearnConfig::default();
    if let Some(m) = a.one("model")? {
        cfg.model = m.to_string();
    }
    if let Some(m) = a.f64_opt("margin")? {
        cfg.margin = m;
    }
    cfg.ceiling_linear = a.f64_opt("ceiling-linear")?;
    cfg.ceiling_joint = a.f64_opt("ceiling-joint")?;
    cfg.learn_readers = a.switch("learn-readers");
    if let Some(n) = a.u64_opt("min-samples")? {
        cfg.min_samples = n;
    }
    if let Some(v) = a.f64_opt("hard-cap-linear")? {
        cfg.hard_cap_linear = v;
    }
    if let Some(v) = a.f64_opt("hard-cap-joint")? {
        cfg.hard_cap_joint = v;
    }
    if let Some(v) = a.f64_opt("outlier-ratio")? {
        cfg.outlier_ratio = v;
    }
    if let Some(n) = a.u64_opt("min-announcements")? {
        cfg.min_participant_announcements = n;
    }
    if let Some(secs) = a.f64_opt("min-duration")? {
        if !(0.0..=86_400.0).contains(&secs) {
            return Err(format!("--min-duration: {secs} must be in [0, 86400] seconds").into());
        }
        cfg.min_participant_duration = Duration::from_secs_f64(secs);
    }
    cfg.accept_participants = a.all("accept-participant").iter().cloned().collect();
    cfg.motion_topics
        .extend(a.all("motion-topic").iter().cloned());
    let force = a.switch("force");
    let out = a.required("out")?;
    let signoff_path = match a.one("signoff")? {
        Some(s) => s.to_string(),
        None => format!("{out}.signoff.json"),
    };
    let report_path = a.one("report")?;
    let inputs = a.inputs()?;
    let input_paths: Vec<&str> = a
        .all("events")
        .iter()
        .chain(a.all("pcap"))
        .map(String::as_str)
        .collect();
    let mut outputs = vec![out, signoff_path.as_str()];
    outputs.extend(report_path);
    distinct_paths(&outputs, &input_paths)?;
    // Refuse now, not after learning (and never leave a partial set).
    precheck_outputs(&outputs, force)?;

    let mut learner = Learner::new(cfg).map_err(|e| e.to_string())?;
    for spec in &inputs {
        let mut src = input::open(spec).map_err(|e| e.to_string())?;
        learner.ingest(src.as_mut()).map_err(|e| e.to_string())?;
    }
    let c = learner.finish();
    // Serialise everything first so a serialisation error writes nothing.
    let profile_text = json(&c.profile)?;
    let signoff_text = json(&c.signoff)?;
    let report_text = json(&c.report)?;
    let mut files = vec![
        (out, profile_text.as_str()),
        (signoff_path.as_str(), signoff_text.as_str()),
    ];
    if let Some(r) = report_path {
        files.push((r, report_text.as_str()));
    }
    write_files(&files, force)?;
    if !a.switch("quiet") {
        print!("{}", c.report);
    }
    eprintln!(
        "wrote draft profile {out} (locked: false): {} participants, {} writer topics, \
         {} services, {} actions, {} raw DDS topics, {} reader topics, \
         {} motion channels; {} anomalies, {} warnings need attention; \
         {} quarantined participant(s); sign-off list {signoff_path} ({} item(s) to confirm)",
        c.profile.participants.len(),
        c.profile.writer_topics.len(),
        c.profile.services.len(),
        c.profile.actions.len(),
        c.profile.raw_dds_topics.len(),
        c.profile.reader_topics.len(),
        c.profile.motion_envelopes.len(),
        c.report.anomalies_total,
        c.report.warn_count(),
        c.report
            .participants
            .values()
            .filter(|p| p.status == robodr_commission::ParticipantStatus::Quarantined)
            .count(),
        c.signoff.items.len()
    );
    Ok(())
}

fn now_unix() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock is before 1970; pass --locked-at".to_string())
}

/// `--locked-at` or the current time.
fn locked_at(a: &Args) -> Result<u64, String> {
    match a.u64_opt("locked-at")? {
        Some(0) => Err("--locked-at must be > 0".into()),
        Some(t) => Ok(t),
        None => now_unix(),
    }
}

/// Seal `profile` and, with a signing key, sign the sealed bytes. Returns
/// `(profile text, signature text)`.
fn seal_and_sign(
    profile: &Profile,
    key: Option<&robodr_blackbox::Ed25519SigningKey>,
) -> Result<(String, Option<String>), String> {
    let text = sealed_text(profile).map_err(|e| format!("serialise: {e}"))?;
    let sig = key
        .map(|k| {
            ProfileSignature::create(text.as_bytes(), k)
                .map(|s| s.to_text())
                .map_err(|e| e.to_string())
        })
        .transpose()?;
    Ok((text, sig))
}

/// Write a locked profile and (if any) its signature as one unit.
fn write_locked(out: &str, text: &str, sig: Option<&str>, force: bool) -> Result<(), String> {
    let sig_path = sig_path_for(Path::new(out)).display().to_string();
    let mut files = vec![(out, text)];
    if let Some(s) = sig {
        files.push((sig_path.as_str(), s));
    }
    write_files(&files, force)
}

/// The metadata `lock` stamps (see USAGE).
fn lock_metadata(a: &Args, draft: &Profile, operator: &str) -> Result<ProfileMetadata, String> {
    let mut platform = a.one("platform")?.map(str::to_string);
    let mut unit_id = a.one("unit-id")?.map(str::to_string);
    let mut version = a.u64_opt("profile-version")?;
    let mut parent_digest = None;
    if let Some(parent) = a.one("parent")? {
        let text = read_text(parent, MAX_PROFILE_BYTES)?;
        let pp = parse_profile_text(&text).map_err(|e| format!("--parent {parent}: {e}"))?;
        let Some(pm) = pp.metadata.as_ref().filter(|_| pp.locked) else {
            return Err(format!(
                "--parent {parent}: not a versioned locked profile (migrate a legacy profile \
                 with `migrate-legacy` first)"
            ));
        };
        if let Some(tk) = a.one("trusted-keys")? {
            let policy = TrustPolicy {
                anchors: Some(load_trust_keys(Path::new(tk)).map_err(|e| e.to_string())?),
                ..Default::default()
            };
            verify_profile_file(Path::new(parent), &policy)
                .map_err(|e| format!("--parent {parent}: {e}"))?
                .map_err(|e| format!("--parent {parent}: {e}"))?;
        }
        if pp.model != draft.model {
            return Err(format!(
                "--parent {parent} is for model {:?}, the draft is {:?}",
                pp.model, draft.model
            ));
        }
        match &platform {
            Some(p) if p != &pm.platform => {
                return Err(format!(
                    "--platform {p:?} differs from the parent's {:?}",
                    pm.platform
                ))
            }
            _ => platform = Some(pm.platform.clone()),
        }
        if unit_id.is_none() {
            unit_id = pm.unit_id.clone();
        } else if pm.unit_id.is_some() && unit_id != pm.unit_id {
            return Err(format!(
                "--unit-id {unit_id:?} differs from the parent's {:?}",
                pm.unit_id
            ));
        }
        let next = pm
            .profile_version
            .checked_add(1)
            .ok_or("parent profile_version is u64::MAX; cannot supersede it")?;
        match version {
            Some(v) if v <= pm.profile_version => {
                return Err(format!(
                    "--profile-version {v} must be higher than the parent's {}",
                    pm.profile_version
                ))
            }
            Some(_) => {}
            None => version = Some(next),
        }
        parent_digest = Some(file_digest(text.as_bytes()));
    }
    let meta = ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: version.ok_or("--profile-version (or --parent) is required")?,
        platform: platform.ok_or("--platform (or --parent) is required")?,
        unit_id,
        locked_by: operator.trim().to_string(),
        locked_at: locked_at(a)?,
        parent_digest,
    };
    let errs = meta.validate();
    if !errs.is_empty() {
        let list: Vec<String> = errs.iter().map(ToString::to_string).collect();
        return Err(format!("profile metadata: {}", list.join("; ")));
    }
    Ok(meta)
}

fn cmd_lock(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "in",
            "out",
            "signoff",
            "hard-cap-linear",
            "hard-cap-joint",
            "platform",
            "unit-id",
            "profile-version",
            "parent",
            "sign-key",
            "trusted-keys",
            "locked-at",
        ],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let caps = hard_caps(&a)?;
    let input = a.required("in")?;
    let out = a.required("out")?;
    let signoff_path = a.required("signoff")?;
    let sig_out = sig_path_for(Path::new(out)).display().to_string();
    let mut inputs = vec![input, signoff_path];
    inputs.extend(a.one("parent")?);
    inputs.extend(a.one("sign-key")?);
    distinct_paths(&[out, sig_out.as_str()], &inputs)?;
    let key = a
        .one("sign-key")?
        .map(|k| load_signing_key(Path::new(k)))
        .transpose()?;
    let draft = read_text(input, MAX_PROFILE_BYTES)?;
    // An unreadable draft is an input error (exit 2), not a refusal.
    let parsed = parse_profile_text(&draft).map_err(|e| format!("{input}: {e}"))?;
    let signoff = load_signoff(signoff_path)?;
    // Flag / parent errors are usage errors (exit 2) and are reported
    // before the lock decision; the operator name is checked by the lock
    // itself (a refusal, exit 1), so a placeholder stands in for it here.
    lock_metadata(&a, &parsed, "pending-sign-off")?;
    match lock_draft_text_with_caps(&draft, &signoff, &caps) {
        Ok(mut locked) => {
            locked.metadata = Some(lock_metadata(&a, &parsed, &signoff.operator)?);
            if let Err(errs) = locked.validate() {
                let list: Vec<String> = errs.iter().map(ToString::to_string).collect();
                return Err(format!("locked profile fails validation: {}", list.join("; ")).into());
            }
            let (text, sig) = seal_and_sign(&locked, key.as_ref())?;
            write_locked(out, &text, sig.as_deref(), a.switch("force"))?;
            let m = locked.metadata.as_ref().expect("set above");
            eprintln!(
                "locked profile {} -> {out} (sealed; profile_version {}, platform {}; signed off \
                 by {:?}; digest {})",
                locked.model,
                m.profile_version,
                m.platform,
                signoff.operator,
                file_digest(text.as_bytes())
            );
            match &key {
                Some(k) => eprintln!(
                    "signed by {} -> {sig_out}",
                    robodr_blackbox::Signer::key_id(k)
                ),
                None => eprintln!(
                    "warning: NOT signed: loaders refuse to enforce it until signed \
                     (`robodr-commission sign --profile {out} --sign-key <key>`)"
                ),
            }
            Ok(())
        }
        Err(reasons) => {
            eprintln!("refusing to lock {input}:");
            for r in reasons {
                eprintln!("  - {r}");
            }
            Err(Failure::Negative)
        }
    }
}

fn cmd_sign(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["profile", "sign-key"], &["force"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let profile = a.required("profile")?;
    let key_path = a.required("sign-key")?;
    let sig_out = sig_path_for(Path::new(profile)).display().to_string();
    distinct_paths(&[sig_out.as_str()], &[profile, key_path])?;
    let key = load_signing_key(Path::new(key_path))?;
    let text = read_text(profile, MAX_PROFILE_BYTES)?;
    let p = parse_profile_text(&text).map_err(|e| format!("{profile}: {e}"))?;
    if !p.locked {
        return Err(format!("{profile}: not locked (drafts are not signed)").into());
    }
    if p.metadata.is_none() {
        return Err(format!(
            "{profile}: legacy locked profile without metadata; use `migrate-legacy`"
        )
        .into());
    }
    let sig = ProfileSignature::create(text.as_bytes(), &key).map_err(|e| e.to_string())?;
    write_file(&sig_out, &sig.to_text(), a.switch("force"))?;
    eprintln!(
        "signed {profile} ({}) by {} -> {sig_out}",
        sig.profile_digest, sig.key_id
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct VerifyReport {
    trusted: bool,
    profile: String,
    digest: Option<String>,
    model: Option<String>,
    locked: Option<bool>,
    profile_version: Option<u64>,
    platform: Option<String>,
    unit_id: Option<String>,
    signed_by: Option<String>,
    rollback: Option<String>,
    revocation_serial: Option<u64>,
    refused: Option<String>,
}

fn cmd_verify_profile(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "profile",
            "trusted-keys",
            "expect-platform",
            "expect-unit",
            "state",
            "allow-rollback",
            "trust-roots",
            "revocations",
        ],
        &["json", "revocations-required"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let path = a.required("profile")?;
    let allow = a.one("allow-rollback")?;
    if let Some(f) = allow {
        validate_rollback_flag(f)?;
    }
    let trusted = a.required("trusted-keys")?;
    let roots = a.one("trust-roots")?;
    let revs = a.one("revocations")?;
    if revs.is_some() && roots.is_none() {
        return Err("--revocations needs --trust-roots".to_string().into());
    }
    let required = a.switch("revocations-required");
    if required && revs.is_none() {
        return Err("--revocations-required needs --revocations"
            .to_string()
            .into());
    }
    let text = read_text(path, MAX_PROFILE_BYTES)?;
    let inputs = TrustInputs {
        trusted_keys: Some(Path::new(trusted)),
        trust_roots: roots.map(Path::new),
        revocation_list: revs.map(Path::new),
        revocation_policy: if required {
            RevocationPolicy::Required
        } else {
            RevocationPolicy::Optional
        },
        expect_platform: a.one("expect-platform")?,
        expect_unit_id: a.one("expect-unit")?,
        state_file: a.one("state")?.map(Path::new),
        allow_rollback: allow,
        chain: None,
    };
    let eval = evaluate_profile_trust(Path::new(path), &text, &inputs);
    let mut r = VerifyReport {
        trusted: false,
        profile: path.to_string(),
        digest: Some(file_digest(text.as_bytes())),
        model: None,
        locked: None,
        profile_version: None,
        platform: None,
        unit_id: None,
        signed_by: None,
        rollback: None,
        revocation_serial: None,
        refused: None,
    };
    match eval.result {
        Ok(acc) => {
            let v = &acc.verified;
            let m = v.profile.metadata.as_ref();
            r.model = Some(v.profile.model.clone());
            r.locked = Some(v.profile.locked);
            r.profile_version = m.map(|m| m.profile_version);
            r.platform = m.map(|m| m.platform.clone());
            r.unit_id = m.and_then(|m| m.unit_id.clone());
            r.signed_by = v.signed_by.clone();
            r.rollback = acc.decision.map(|d| format!("{d:?}"));
            r.revocation_serial = acc.record.as_ref().and_then(|s| s.revocation_serial);
            r.trusted = v.profile.locked;
            if !v.profile.locked {
                r.refused = Some("unlocked draft: observe-only, nothing to trust".into());
            }
        }
        Err(e) => r.refused = Some(e.to_string()),
    }
    if a.switch("json") {
        print!("{}", json(&r)?);
    } else if r.trusted {
        println!(
            "TRUSTED {path}: model {:?}, profile_version {}, platform {:?}, unit {:?}, signed by \
             {:?}, digest {}{}{}",
            r.model.as_deref().unwrap_or_default(),
            r.profile_version.unwrap_or_default(),
            r.platform.as_deref().unwrap_or_default(),
            r.unit_id,
            r.signed_by.as_deref().unwrap_or_default(),
            r.digest.as_deref().unwrap_or_default(),
            r.rollback
                .as_ref()
                .map(|d| format!(", anti-rollback: {d}"))
                .unwrap_or_default(),
            r.revocation_serial
                .map(|n| format!(", revocation list serial {n}"))
                .unwrap_or_default()
        );
    } else {
        println!(
            "REFUSED {path}: {}",
            r.refused.as_deref().unwrap_or("not trusted")
        );
        if let Some(d) = &r.digest {
            println!("  digest {d}");
        }
    }
    if r.trusted {
        Ok(())
    } else {
        Err(Failure::Negative)
    }
}

fn cmd_keygen(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["out", "trust-out", "key-id"], &["roots"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let out = a.required("out")?;
    let trust_out = a.required("trust-out")?;
    let pub_out = public_key_path(Path::new(out)).display().to_string();
    distinct_paths(&[out, pub_out.as_str(), trust_out], &[])?;
    precheck_outputs(&[out, pub_out.as_str(), trust_out], false)?;
    let (kf, vk) = new_signing_key(a.one("key-id")?)?;
    let public = kf.to_public().map_err(|e| e.to_string())?;
    kf.write_new(Path::new(out))
        .map_err(|e| format!("{out}: {e}"))?;
    if let Err(e) = public.write_new(Path::new(&pub_out)) {
        let _ = std::fs::remove_file(out);
        return Err(format!("{pub_out}: {e}").into());
    }
    let roots = a.switch("roots");
    let list = if roots {
        trust_roots_text(&[vk])
    } else {
        trust_keys_text(&[vk])
    };
    if let Err(e) = write_file(trust_out, &list, false) {
        let _ = std::fs::remove_file(out);
        let _ = std::fs::remove_file(&pub_out);
        return Err(e.into());
    }
    eprintln!(
        "wrote Ed25519 {} key {out} (mode 0600, key id {}), its public key {pub_out} and {} \
         {trust_out}; keep the key off the robot, install the {} on it",
        if roots {
            "trust-root"
        } else {
            "profile signing"
        },
        kf.key_id,
        if roots {
            "trust-roots file"
        } else {
            "trust file"
        },
        if roots { "roots file" } else { "trust file" },
    );
    Ok(())
}

fn cmd_trust_keys(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &["out", "pub", "min-profile-version", "sign-key"],
        &["force", "roots"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let out = a.required("out")?;
    let pubs: Vec<&str> = a.all("pub").iter().map(String::as_str).collect();
    if pubs.is_empty() {
        return Err("--pub is required (one per trusted key)".to_string().into());
    }
    let floor = a.u64_opt("min-profile-version")?;
    let sign_key = a.one("sign-key")?;
    let roots = a.switch("roots");
    if roots && (floor.is_some() || sign_key.is_some()) {
        return Err(
            "--roots writes a trust-roots file; --min-profile-version / --sign-key belong to a \
             profile trust file"
                .to_string()
                .into(),
        );
    }
    if floor == Some(0) {
        return Err("--min-profile-version must be >= 1".to_string().into());
    }
    if floor.is_some() && sign_key.is_none() {
        return Err(
            "--min-profile-version needs --sign-key ROOT.key (loaders refuse an unsigned \
             floor)"
                .to_string()
                .into(),
        );
    }
    let sig_out = sig_path_for(Path::new(out)).display().to_string();
    let mut inputs = pubs.clone();
    inputs.extend(sign_key);
    let outputs: Vec<&str> = if sign_key.is_some() {
        vec![out, sig_out.as_str()]
    } else {
        vec![out]
    };
    distinct_paths(&outputs, &inputs)?;
    let paths: Vec<&Path> = pubs.iter().map(|p| Path::new(*p)).collect();
    let keys = verifying_keys_from_public_files(&paths)?;
    if roots {
        write_file(out, &trust_roots_text(&keys), a.switch("force"))?;
        eprintln!(
            "wrote trust-roots file {out} with {} key(s); install it on the robot \
             (profile_trust.trust_roots)",
            keys.len()
        );
        return Ok(());
    }
    let text = trust_file_text(&keys, floor);
    match sign_key {
        None => {
            write_file(out, &text, a.switch("force"))?;
            eprintln!(
                "wrote trust file {out} with {} key(s); install it on the robot",
                keys.len()
            );
        }
        Some(k) => {
            let root = load_signing_key(Path::new(k))?;
            if keys.iter().any(|p| p.as_bytes() == &root.public_key()) {
                return Err(format!(
                    "{k}: the trust root must not be one of the profile keys it signs for"
                )
                .into());
            }
            let sig = ProfileSignature::create_for(SigKind::TrustFile, text.as_bytes(), &root)
                .map_err(|e| e.to_string())?;
            write_files(
                &[(out, &text), (&sig_out, &sig.to_text())],
                a.switch("force"),
            )?;
            eprintln!(
                "wrote trust file {out} with {} key(s){} and its root signature {sig_out} (by \
                 {}); install both on the robot",
                keys.len(),
                floor
                    .map(|f| format!(", min_profile_version {f}"))
                    .unwrap_or_default(),
                sig.key_id
            );
        }
    }
    Ok(())
}

fn cmd_revoke(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "sign-key",
            "out",
            "digest",
            "revoke-profile",
            "key-id",
            "base",
            "trust-roots",
            "serial",
            "issued-at",
        ],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let out = a.required("out")?;
    let key_path = a.required("sign-key")?;
    let base_path = a.one("base")?;
    let roots_path = a.one("trust-roots")?;
    let mut inputs = vec![key_path];
    inputs.extend(base_path);
    inputs.extend(roots_path);
    let profiles: Vec<&str> = a.all("revoke-profile").iter().map(String::as_str).collect();
    inputs.extend(profiles.iter().copied());
    distinct_paths(&[out], &inputs)?;
    precheck_outputs(&[out], a.switch("force"))?;
    let root = load_signing_key(Path::new(key_path))?;
    let roots = roots_path
        .map(|p| load_trust_roots(Path::new(p)).map_err(|e| e.to_string()))
        .transpose()?;
    if let Some(r) = &roots {
        if !r
            .public_keys
            .iter()
            .any(|k| k.as_bytes() == &root.public_key())
        {
            return Err(format!(
                "{key_path}: not one of the trust roots in {}",
                roots_path.unwrap_or_default()
            )
            .into());
        }
    }
    let base = match base_path {
        None => None,
        Some(b) => {
            let Some(r) = &roots else {
                return Err(
                    "--base needs --trust-roots (the base list is verified first)"
                        .to_string()
                        .into(),
                );
            };
            match load_revocation_list(Path::new(b), r).map_err(|e| e.to_string())? {
                Some(l) => Some(l),
                None => return Err(format!("{b}: no such file").into()),
            }
        }
    };
    let mut digests: Vec<String> = base
        .as_ref()
        .map(|l| l.revoked_digests.clone())
        .unwrap_or_default();
    let mut key_ids: Vec<String> = base
        .as_ref()
        .map(|l| l.revoked_key_ids.clone())
        .unwrap_or_default();
    for d in a.all("digest") {
        validate_rollback_flag(d).map_err(|_| {
            format!("--digest {d:?} must be sha256:<64 lower-case hex> (verify-profile prints it)")
        })?;
        digests.push(d.clone());
    }
    for p in &profiles {
        let bytes = std::fs::read(p).map_err(|e| format!("{p}: {e}"))?;
        digests.push(file_digest(&bytes));
    }
    key_ids.extend(a.all("key-id").iter().cloned());
    let base_serial = base.as_ref().map(|l| l.serial).unwrap_or(0);
    let serial = match a.u64_opt("serial")? {
        Some(n) if n <= base_serial => {
            return Err(format!(
                "--serial {n} must be higher than the base list's serial {base_serial}"
            )
            .into())
        }
        Some(n) => n,
        None => base_serial
            .checked_add(1)
            .ok_or_else(|| "base serial is at its maximum".to_string())?,
    };
    let issued_at = match a.u64_opt("issued-at")? {
        Some(t) => t,
        None => now_unix()?,
    };
    let list = RevocationList::create(serial, issued_at, digests, key_ids, &root)?;
    write_file(out, &list.to_text(), a.switch("force"))?;
    eprintln!(
        "wrote revocation list {out}: serial {}, {} revoked digest(s), {} revoked key id(s), \
         signed by {}, digest {}; install it on every robot (profile_trust.revocation_list)",
        list.serial,
        list.revoked_digests.len(),
        list.revoked_key_ids.len(),
        list.signature.key_id,
        list.digest()
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct RevocationReport {
    valid: bool,
    list: String,
    serial: Option<u64>,
    issued_at: Option<u64>,
    digest: Option<String>,
    signed_by: Option<String>,
    revoked_digests: Vec<String>,
    revoked_key_ids: Vec<String>,
    accepted_serial: Option<u64>,
    refused: Option<String>,
}

fn cmd_verify_revocations(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["list", "trust-roots", "state"], &["json"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let path = a.required("list")?;
    let roots =
        load_trust_roots(Path::new(a.required("trust-roots")?)).map_err(|e| e.to_string())?;
    let state = a
        .one("state")?
        .map(|p| load_state(Path::new(p)).map_err(|e| e.to_string()))
        .transpose()?
        .flatten();
    let mut r = RevocationReport {
        valid: false,
        list: path.to_string(),
        serial: None,
        issued_at: None,
        digest: None,
        signed_by: None,
        revoked_digests: Vec::new(),
        revoked_key_ids: Vec::new(),
        accepted_serial: state.as_ref().and_then(|s| s.revocation_serial),
        refused: None,
    };
    match load_revocation_list(Path::new(path), &roots) {
        Ok(None) => r.refused = Some("no such file".into()),
        Err(e) => r.refused = Some(e.to_string()),
        Ok(Some(l)) => {
            r.serial = Some(l.serial);
            r.issued_at = Some(l.issued_at);
            r.digest = Some(l.digest());
            r.signed_by = Some(l.signature.key_id.clone());
            r.revoked_digests = l.revoked_digests.clone();
            r.revoked_key_ids = l.revoked_key_ids.clone();
            r.valid = true;
            let accepted = state
                .as_ref()
                .and_then(|s| Some((s.revocation_serial?, s.revocation_digest.clone()?)));
            if let Some((n, d)) = accepted {
                if l.serial < n {
                    r.valid = false;
                    r.refused = Some(format!(
                        "serial {} is older than the accepted serial {n} (rollback)",
                        l.serial
                    ));
                } else if l.serial == n && l.digest() != d {
                    r.valid = false;
                    r.refused = Some(format!(
                        "serial {n} was accepted with other content (equivocation)"
                    ));
                }
            }
        }
    }
    if a.switch("json") {
        print!("{}", json(&r)?);
    } else if r.valid {
        println!(
            "VALID {path}: serial {}, issued_at {}, {} revoked digest(s), {} revoked key id(s), \
             signed by {:?}, digest {}",
            r.serial.unwrap_or_default(),
            r.issued_at.unwrap_or_default(),
            r.revoked_digests.len(),
            r.revoked_key_ids.len(),
            r.signed_by.as_deref().unwrap_or_default(),
            r.digest.as_deref().unwrap_or_default()
        );
    } else {
        println!(
            "REFUSED {path}: {}",
            r.refused.as_deref().unwrap_or("not valid")
        );
    }
    if r.valid {
        Ok(())
    } else {
        Err(Failure::Negative)
    }
}

fn cmd_migrate_legacy(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "in",
            "out",
            "platform",
            "unit-id",
            "profile-version",
            "operator",
            "sign-key",
            "locked-at",
        ],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let input = a.required("in")?;
    let out = a.required("out")?;
    let key_path = a.required("sign-key")?;
    let sig_out = sig_path_for(Path::new(out)).display().to_string();
    distinct_paths(&[out, sig_out.as_str()], &[input, key_path])?;
    let key = load_signing_key(Path::new(key_path))?;
    let text = read_text(input, MAX_PROFILE_BYTES)?;
    let mut p = parse_profile_text(&text).map_err(|e| format!("{input}: {e}"))?;
    if !p.locked {
        return Err(format!("{input}: not locked; use `lock` for drafts").into());
    }
    if p.metadata.is_some() {
        return Err(format!("{input}: already has metadata (not a legacy profile)").into());
    }
    let meta = ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: a
            .u64_opt("profile-version")?
            .ok_or_else(|| "--profile-version is required".to_string())?,
        platform: a.required("platform")?.to_string(),
        unit_id: a.one("unit-id")?.map(str::to_string),
        locked_by: a.required("operator")?.trim().to_string(),
        locked_at: locked_at(&a)?,
        parent_digest: Some(file_digest(text.as_bytes())),
    };
    p.metadata = Some(meta);
    if let Err(errs) = p.validate() {
        let list: Vec<String> = errs.iter().map(ToString::to_string).collect();
        return Err(format!("migrated profile fails validation: {}", list.join("; ")).into());
    }
    let (out_text, sig) = seal_and_sign(&p, Some(&key))?;
    write_locked(out, &out_text, sig.as_deref(), a.switch("force"))?;
    eprintln!(
        "migrated legacy profile {input} -> {out} + {sig_out} (content unchanged; parent \
         digest {}; new digest {})",
        file_digest(text.as_bytes()),
        file_digest(out_text.as_bytes())
    );
    Ok(())
}

fn cmd_diff(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &[], &["json"])?;
    let [old, new] = a.positionals.as_slice() else {
        return Err(
            "diff takes exactly two profile files: <old.json> <new.json>"
                .to_string()
                .into(),
        );
    };
    let d = diff(&load_profile(old)?, &load_profile(new)?);
    if a.switch("json") {
        print!("{}", json(&d)?);
    } else {
        print!("{d}");
    }
    if d.is_empty() {
        Ok(())
    } else {
        Err(Failure::Negative)
    }
}

fn cmd_check(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["profile", "events", "pcap"], &["json"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let profile = load_valid_profile(a.required("profile")?)?;
    let inputs = a.inputs()?;
    let mut checker = Checker::new(&profile);
    for spec in &inputs {
        let mut src = input::open(spec).map_err(|e| e.to_string())?;
        checker.ingest(src.as_mut()).map_err(|e| e.to_string())?;
    }
    let r = checker.finish();
    if a.switch("json") {
        print!("{}", json(&r)?);
    } else {
        print!("{r}");
    }
    if r.deviations_total == 0 {
        Ok(())
    } else {
        Err(Failure::Negative)
    }
}

fn cmd_signoff(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["in", "out"], &["force"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let input = a.required("in")?;
    let out = a.required("out")?;
    distinct_paths(&[out], &[input])?;
    let text = read_text(input, MAX_PROFILE_BYTES)?;
    let p = parse_profile_text(&text).map_err(|e| format!("{input}: {e}"))?;
    if p.locked {
        return Err(format!("{input}: already locked").into());
    }
    let mut s = Signoff::for_profile(&p);
    // Bind to the bytes on disk (they may differ from our canonical form if
    // the draft was edited by hand).
    s.rebind(robodr_commission::signoff::sha256_hex(text.as_bytes()));
    write_file(out, &json(&s)?, a.switch("force"))?;
    eprintln!(
        "wrote conservative sign-off list {out} ({} item(s)): review each, set \"confirmed\": \
         true and fill \"operator\"",
        s.items.len()
    );
    Ok(())
}

fn cmd_merge(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &["out", "hard-cap-linear", "hard-cap-joint"],
        &["force"],
    )?;
    let caps = hard_caps(&a)?;
    let out = a.required("out")?;
    if a.positionals.is_empty() {
        return Err("merge needs at least one profile file".to_string().into());
    }
    let ins: Vec<&str> = a.positionals.iter().map(String::as_str).collect();
    distinct_paths(&[out], &ins)?;
    let profiles = a
        .positionals
        .iter()
        .map(|p| load_profile(p))
        .collect::<Result<Vec<_>, _>>()?;
    let m = merge_profiles_with_caps(&profiles, &caps).map_err(|e| e.to_string())?;
    write_file(out, &json(&m)?, a.switch("force"))?;
    eprintln!(
        "merged {} profiles -> {out} (locked: false; provenance is lost: create a sign-off \
         list with `robodr-commission signoff --in {out} --out <file>`, review it, then lock)",
        profiles.len()
    );
    Ok(())
}
