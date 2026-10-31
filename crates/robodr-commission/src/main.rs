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
//! After its companion files, `learn` (and `signoff` in list mode) writes
//! an output manifest `<draft>.manifest.json` last (see
//! `robodr_commission::ops`, "Output manifest"); `lock` and `check` refuse a
//! draft whose manifest is missing or does not match.
//!
//! Operator sign-off is signed: `signoff --signoff S --sign-key OP.key`
//! adds the operator's Ed25519 signature over the confirmed list's exact
//! bytes to `S.sig`; `lock --operators operators.json` requires valid
//! signatures from listed operators (see `robodr_commission::signoff`).
//!
//! Signing: `lock --sign-key` (and `sign`, `migrate-legacy`) write the
//! detached Ed25519 signature `<out>.sig` over the exact sealed bytes, as a
//! unit with the profile. `verify-profile` runs the same trust check the
//! loaders run (see `robodr_commission::trust`). Signing keys are read only
//! from mode-0600 key files, never from the command line, or stay in a
//! token / HSM behind a `robodr-signer/v1` signer file (every `--sign-key`
//! goes through `robodr_signer::load`; SALES-READINESS T36).

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_blackbox::keys::public_key_path;
use robodr_commission::input::{self, InputSpec};
use robodr_commission::learner::DiscoveryServer;
use robodr_commission::ops::{
    lock_signed_draft, manifest_path_for, verify_manifest, Manifest, OperatorPolicy,
};
use robodr_commission::profile_file::{check_destination, read_regular_file, MAX_PROFILE_BYTES};
use robodr_commission::signoff::{
    draft_digest, required_items, satisfies, sha256_hex, signoff_file_digest, signoff_sig_path,
    OperatorTrust, SignoffSignatures, MAX_OPERATORS_BYTES,
};
use robodr_commission::trust::{
    attestation_for, evaluate_profile_trust, file_digest, key_fingerprint, load_revocation_list,
    load_state, load_trust_keys, load_trust_roots, new_signing_key, sig_path_for,
    trust_file_text_with, trust_keys_text, trust_roots_text, validate_rollback_flag,
    verify_attestation, verify_profile_file, verifying_keys_from_public_files, ProfileSignature,
    RevocationList, RevocationPolicy, SigKind, TrustFileOptions, TrustInputs, TrustPolicy,
};
use robodr_commission::{
    diff, merge_profiles_with_caps, parse_profile_text, sealed_text, to_json, write_files_atomic,
    Checker, HardCaps, LearnConfig, Learner, LockRefusal, Signoff,
};
use robodr_events::profile::{Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

mod wp6;

const USAGE: &str = "\
robodr-commission: learn, review, lock and verify a RoboDR model profile

USAGE:
  robodr-commission learn (--events <run.jsonl> | --pcap <run.pcap[ng]>) [...]
                          [--model NAME] [--margin 1.1] [--min-samples 30]
                          [--ceiling-linear M_PER_S] [--ceiling-joint RAD_PER_S]
                          [--hard-cap-linear 10] [--hard-cap-joint 10]
                          [--hard-cap-torque 400] [--hard-cap-kp 1000]
                          [--hard-cap-position-step 0.5]
                          [--min-announcements 2] [--min-duration SECS]
                          [--outlier-ratio 3]
                          [--accept-participant GUID]... [--motion-topic /T]...
                          [--discovery-server PREFIX|PREFIX@IP|IP]...
                          [--trusted-discovery-server PREFIX@IP|IP]...
                          [--learn-readers] [--no-identities]
                          [--unitree-legacy] [--unitree-legacy-port N]...
                          --out profile.json [--signoff signoff.json]
                          [--report report.json] [--quiet] [--force]
  robodr-commission lock    --in profile.json --signoff signoff.json --out locked.json
                          --operators operators.json [--motion-quorum N] [--no-manifest]
                          (--parent previous-locked.json | --platform P --profile-version N)
                          [--platform P] [--unit-id U] [--profile-version N]
                          [--sign-key signing.key] [--trusted-keys trust.json]
                          [--locked-at UNIX_SECS]
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]
                          [--hard-cap-torque 400] [--hard-cap-kp 1000]
                          [--hard-cap-position-step 0.5]
  robodr-commission sign    --profile locked.json --sign-key signing.key
                          [--operators operators.json] [--allow-unattested] [--force]
  robodr-commission sign-firewall --firewall firewall.json --profile locked.json
                          --sign-key signing.key [--force]
  robodr-commission verify-profile --profile locked.json --trusted-keys trust.json
                          [--expect-platform P] [--expect-unit U]
                          [--state profile-state.json] [--allow-rollback sha256:HEX]
                          [--trust-roots roots.json [--revocations revocations.json
                           [--revocations-required]]] [--json]
  robodr-commission keygen  --out signing.key --trust-out trust.json [--key-id ID] [--roots]
  robodr-commission trust-keys --out trust.json --pub KEY.pub [--pub KEY2.pub]... [--force]
                          [--roots | [--min-profile-version N] [--sign-key ROOT.key]
                           [--operators operators.json]
                           [--require-attestation | --no-require-attestation]]
  robodr-commission revoke  --sign-key ROOT.key --out revocations.json --platform P
                          [--digest sha256:HEX]... [--revoke-profile FILE]...
                          [--revoke-key KEY.pub]... [--key-fingerprint sha256:HEX]...
                          [--base previous.json --trust-roots roots.json]
                          [--serial N] [--issued-at UNIX_SECS] [--force]
  robodr-commission verify-revocations --list revocations.json --trust-roots roots.json
                          [--state profile-state.json] [--json]
  robodr-commission migrate-legacy --in legacy-locked.json --out locked.json
                          --platform P --profile-version N --operator NAME
                          --sign-key signing.key [--unit-id U] [--locked-at UNIX_SECS]
                          [--force]
  robodr-commission signoff --in profile.json --out signoff.json [--force]
  robodr-commission signoff --signoff signoff.json --sign-key operator.key
                          [--in profile.json] [--operators operators.json] [--force]
  robodr-commission operators --out operators.json --operator NAME=KEY.pub [...]
                          [--motion-quorum N] [--force]
  robodr-commission diff    <old.json> <new.json> [--json]
  robodr-commission check   --profile locked.json (--events <f> | --pcap <f>) [...] [--json]
                          [--unitree-legacy] [--unitree-legacy-port N]...
  robodr-commission bind    --in draft.json --out bound.json [--signoff draft.signoff.json]
                          [--response-policy policy.json] [--motion-firewall firewall.json]
                          [--joint-firewall joint.json] [--executor-config executor.json]
                          [--force]
  robodr-commission firewall-draft --in draft.json --report report.json --out firewall.json
                          --max-angular RAD_PER_S [--ceiling-linear M_PER_S]
                          [--morphology wheeled|quadruped|humanoid|arm|other] [--force]
  robodr-commission report-html --report report.json --out report.html
                          [--signoff signoff.json [--operators operators.json]]
                          [--note TEXT] [--force]
  robodr-commission poc-init --dir DIR [--operator NAME]
  robodr-commission merge   --out merged.json <a.json> <b.json> [...]
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]
                          [--hard-cap-torque 400] [--hard-cap-kp 1000]
                          [--hard-cap-position-step 0.5]

  --events: JSON Lines of RobotEvent. --pcap: pcap or pcapng capture of the
  robot bus (discovery, plus Twist / TwistStamped / JointTrajectory commands
  decoded from user data for envelopes). Both repeat and
  mix; every file is one run.
  --unitree-legacy: also decode Unitree legacy UDP (Go1 generation,
  unitree_legged_sdk) in every --pcap, on the SDK's ports 8007 8080 8082
  8090 (--unitree-legacy-port N...: exactly these): HighCmd / decodable
  LowCmd become commands on /unitree_legacy/high_cmd and
  /unitree_legacy/low_cmd (envelopes learned as usual; the report lists
  the command senders' IPs for the sensor's unitree_legacy.command_senders).
  --learn-readers: also learn reader_topics, which turns reader-topic
  enforcement on (off by default: a policy choice for the OEM).
  Identities: DDS draws a new GUID prefix per process start, so learn also
  writes participant_identities (source IPs + RTPS vendor + ROS nodes per
  accepted participant); the sensor maps a restarted process's new GUID to
  them. Each identity is a sign-off item. --no-identities: GUIDs only (the
  profile then matches only the processes of the learned run).
  Anti-poisoning: participants announced fewer than --min-announcements
  times (or, in captures, seen for less than --min-duration seconds) are
  quarantined: not learned, nor their endpoints or motion samples. Use
  --accept-participant to override (it becomes a sign-off item). No
  envelope exceeds --hard-cap-linear / --hard-cap-joint (and, for low-level
  joint commands, --hard-cap-torque / --hard-cap-kp /
  --hard-cap-position-step), and lock and merge refuse any bound above them
  (pass the same values used for learn). A
  dimension never observed on a channel is bounded at its ceiling or 0
  (deny), never left unlimited. --outlier-ratio: max > ratio x p99 on an
  envelope needs sign-off. Endpoints announced under another participant's
  GUID, or from an IP that is not one of the owner's commissioned IPs, are
  not learned (sign-off item endpoint_sender_mismatch), unless relayed by a
  configured discovery server: --discovery-server (known: relayed copies of
  the owner's own announcements are not flagged) or
  --trusted-discovery-server (relayed endpoints of accepted participants
  are learned; a trusted server must be pinned by IP (PREFIX@IP or IP):
  a GUID prefix alone is forgeable by any host).
  learn writes a sign-off list (default <out>.signoff.json) and, last, the
  manifest <out>.manifest.json binding draft, list and report; lock and
  check refuse a draft whose companion files do not match it (lock
  --no-manifest: drafts from before manifests). lock refuses until a named
  \"operator\" has set \"confirmed\": true on every item AND signed the
  list: signoff --signoff S --sign-key OP.key appends the operator's
  Ed25519 signature over the list's exact bytes to S.sig; lock --operators
  requires valid signatures from keys in that trust list (built by
  `operators`), the named operator among the signers, and motion_quorum
  distinct operators when the list has motion items (two-person rule;
  --motion-quorum can only raise it).
  signoff --in/--out builds a conservative list for an edited or merged
  draft (and writes its manifest).
  lock stamps metadata (schema/profile version, platform, unit, locked_by =
  sign-off operator, locked_at, parent digest): with --parent the version
  defaults to the parent's + 1 and must be higher, platform/unit default to
  the parent's, and the parent's file digest is recorded (rollback lineage).
  --sign-key writes <out>.sig (Ed25519 over the exact sealed bytes) with
  the profile; loaders refuse a locked profile without a valid signature
  from a trusted key. lock also embeds the signed sign-off and its operator
  signatures in metadata.attestation, which loaders verify against the
  trust file's operators and motion_quorum (two-person rule on the unit;
  required by default with trust roots). sign refuses a profile without
  that attestation unless --allow-unattested (--operators: verify it). keygen makes an Ed25519 key file (mode 0600), its
  public key file <out>.pub and a trust file holding the public key. Key
  files are robodr-blackbox's (robodr-blackbox-key/v2): a key from
  `robodr-blackbox keygen` signs profiles too. Every --sign-key also takes
  a robodr-signer/v1 signer file instead: the key stays in a PKCS#11
  token or HSM and an external signer command (the shipped
  /usr/lib/robodr/robodr-signer-pkcs11) signs; every signature is checked
  against the public key pinned in that file (crates/robodr-signer). trust-keys builds a trust
  file from Ed25519 .pub files (secret key files are refused). verify-profile is read-only (exit 0
  trusted, 1 refused).
  Trust roots (keygen/trust-keys --roots: robodr-trust-roots/v1) sign the
  revocation list and the trust file; they must differ from every profile
  signing key and operator key. With trust roots configured a loader
  refuses an unsigned trust file. trust-keys --sign-key ROOT.key writes
  trust.json plus trust.json.sig; --min-profile-version N adds a floor (no
  loader accepts it unsigned, not overridable by allow_rollback, never
  lowered by an older trust file); --operators embeds the operators list
  (who may attest; required with roots unless --no-require-attestation).
  revoke signs a robodr-profile-revocations/v2 list for one --platform of
  revoked profile digests and signing keys by public-key fingerprint
  (--revoke-key KEY.pub or --key-fingerprint; keygen prints it); --base
  carries over a previous list (verified under --trust-roots) and the
  serial defaults to its serial + 1 (else 1); a loader refuses a list
  older than the last accepted one or for another platform.
  verify-revocations checks a list (exit 0 valid and not older than
  --state, 1 refused). migrate-legacy re-issues a locked profile from
  before metadata existed (content unchanged, its digest recorded as
  parent).
  bind writes the digest of each safety-relevant file into a copy of the
  draft (bound_config: response_policy, motion_firewall, joint_firewall,
  executor_motion = the executor.json `motion` section) plus a sign-off
  list with one bound_config item per file (a motion item: motion_quorum
  applies) and the manifest. After lock + sign the unit honours
  oem_validated / the firewall envelope only for exactly these files.
  firewall-draft proposes the Motion Firewall channel file from a learn
  report (envelopes capped by the OEM ceilings, observed writers as
  allowed_sources); exit 1 when channels still need the OEM's specs.
  report-html renders a learn report (and sign-off state) as one inert
  HTML page for review, archive and print-to-PDF; the sign-off's
  signatures are shown as UNVERIFIED key ids unless --operators is given
  (then checked against it).
  poc-init creates a LAB-ONLY single-operator signing chain (keys, roots,
  operators, root-signed trust file marked lab_only) for a proof of
  concept; units accept it but report it loudly. Never for production.
  Outputs never overwrite an existing file or follow a symlink unless
  --force (symlinks are refused even then).

EXIT: 0 ok/clean, 1 deviations / differences / lock refused, 2 error.
";

/// The legacy UDP ports of `unitree_legged_sdk` (`udp.h` and its
/// examples): 8007 low-level server, 8082 high-level server, 8080 / 8090
/// client. Same list as the sensor's default.
const UNITREE_LEGACY_DEFAULT_PORTS: [u16; 4] = [8007, 8080, 8082, 8090];

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

    /// `--unitree-legacy` (the SDK's default legacy UDP ports) and / or
    /// `--unitree-legacy-port N`... (exactly these ports).
    fn input_options(&self) -> Result<input::InputOptions, String> {
        let mut o = input::InputOptions::default();
        for v in self.all("unitree-legacy-port") {
            let p = v
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("--unitree-legacy-port: {v:?} is not a UDP port"))?;
            o.unitree_legacy_ports.insert(p);
        }
        if self.switch("unitree-legacy") && o.unitree_legacy_ports.is_empty() {
            o.unitree_legacy_ports = UNITREE_LEGACY_DEFAULT_PORTS.into_iter().collect();
        }
        if o.unitree_legacy_ports.len() > robodr_capture::MAX_LEGACY_UDP_PORTS {
            return Err(format!(
                "--unitree-legacy-port: at most {} ports",
                robodr_capture::MAX_LEGACY_UDP_PORTS
            ));
        }
        Ok(o)
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
        "sign-firewall" => cmd_sign_firewall(rest),
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
        "operators" => cmd_operators(rest),
        "bind" => wp6::cmd_bind(rest),
        "firewall-draft" => wp6::cmd_firewall_draft(rest),
        "report-html" => wp6::cmd_report_html(rest),
        "poc-init" => wp6::cmd_poc_init(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        "--version" | "version" => {
            println!(
                "{}",
                robodr_buildinfo::version_line("robodr-commission", env!("CARGO_PKG_VERSION"))
            );
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

/// Publish `files` as a unit, then the manifest built by `make` (after the
/// files are durable). An existing manifest is removed before anything is
/// published (it would describe the previous output set).
fn publish_with_manifest(
    files: &[(&str, &str)],
    manifest: &str,
    force: bool,
    replace_manifest: bool,
    make: impl FnOnce(&Path) -> Manifest,
) -> Result<(), String> {
    let mp = Path::new(manifest);
    for (p, _) in files {
        check_destination(Path::new(p), force).map_err(|e| format!("{p}: {e}"))?;
    }
    check_destination(mp, replace_manifest).map_err(|e| format!("{manifest}: {e}"))?;
    match std::fs::symlink_metadata(mp) {
        Ok(m) if m.is_file() => {
            std::fs::remove_file(mp).map_err(|e| format!("{manifest}: {e}"))?;
            if let Some(d) = mp.parent().filter(|d| !d.as_os_str().is_empty()) {
                if let Ok(d) = std::fs::File::open(d) {
                    let _ = d.sync_all();
                }
            }
        }
        _ => {}
    }
    write_files(files, force)?;
    let text = make(mp).to_text();
    write_file(manifest, &text, false)
}

/// Fail early (before reading inputs) if an output could not be written.
fn precheck_outputs(paths: &[&str], force: bool) -> Result<(), String> {
    for p in paths {
        check_destination(Path::new(p), force).map_err(|e| format!("{p}: {e}"))?;
    }
    Ok(())
}

/// `--hard-cap-linear` / `--hard-cap-joint` / `--hard-cap-torque` /
/// `--hard-cap-kp` / `--hard-cap-position-step` (defaults: learn's
/// defaults).
fn hard_caps(a: &Args) -> Result<HardCaps, String> {
    let mut caps = HardCaps::default();
    for (name, slot) in [
        ("hard-cap-linear", &mut caps.linear),
        ("hard-cap-joint", &mut caps.joint),
        ("hard-cap-torque", &mut caps.torque),
        ("hard-cap-kp", &mut caps.kp),
        ("hard-cap-position-step", &mut caps.position_step),
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

/// The operator signatures of a sign-off (`None` if the file is absent).
fn load_signoff_sigs(path: &str) -> Result<Option<SignoffSignatures>, String> {
    match read_regular_file(Path::new(path), MAX_OPERATORS_BYTES) {
        Ok(t) => SignoffSignatures::parse(&t)
            .map(Some)
            .map_err(|e| format!("{path}: not a sign-off signature file: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{path}: {e}")),
    }
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
            "hard-cap-torque",
            "hard-cap-kp",
            "hard-cap-position-step",
            "min-announcements",
            "min-duration",
            "accept-participant",
            "motion-topic",
            "outlier-ratio",
            "discovery-server",
            "trusted-discovery-server",
            "unitree-legacy-port",
        ],
        &[
            "quiet",
            "learn-readers",
            "no-identities",
            "force",
            "unitree-legacy",
        ],
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
    cfg.no_identities = a.switch("no-identities");
    if let Some(n) = a.u64_opt("min-samples")? {
        cfg.min_samples = n;
    }
    if let Some(v) = a.f64_opt("hard-cap-linear")? {
        cfg.hard_cap_linear = v;
    }
    if let Some(v) = a.f64_opt("hard-cap-joint")? {
        cfg.hard_cap_joint = v;
    }
    if let Some(v) = a.f64_opt("hard-cap-torque")? {
        cfg.hard_cap_torque = v;
    }
    if let Some(v) = a.f64_opt("hard-cap-kp")? {
        cfg.hard_cap_kp = v;
    }
    if let Some(v) = a.f64_opt("hard-cap-position-step")? {
        cfg.hard_cap_position_step = v;
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
    for (name, trusted) in [
        ("discovery-server", false),
        ("trusted-discovery-server", true),
    ] {
        for spec in a.all(name) {
            cfg.discovery_servers
                .push(DiscoveryServer::parse(spec, trusted).map_err(|e| format!("--{name}: {e}"))?);
        }
    }
    let force = a.switch("force");
    let out = a.required("out")?;
    let signoff_path = match a.one("signoff")? {
        Some(s) => s.to_string(),
        None => format!("{out}.signoff.json"),
    };
    let report_path = a.one("report")?;
    let manifest = manifest_path_for(Path::new(out)).display().to_string();
    let inputs = a.inputs()?;
    let input_paths: Vec<&str> = a
        .all("events")
        .iter()
        .chain(a.all("pcap"))
        .map(String::as_str)
        .collect();
    let mut outputs = vec![out, signoff_path.as_str(), manifest.as_str()];
    outputs.extend(report_path);
    distinct_paths(&outputs, &input_paths)?;
    // Refuse now, not after learning (and never leave a partial set).
    precheck_outputs(&outputs, force)?;

    let input_opts = a.input_options()?;
    let mut learner = Learner::new(cfg).map_err(|e| e.to_string())?;
    for spec in &inputs {
        let mut src = input::open_with_options(spec, &input_opts).map_err(|e| e.to_string())?;
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
    // The manifest goes last: a stale one is removed first, so a crash in
    // between leaves no manifest (lock refuses) rather than an old one.
    publish_with_manifest(&files, &manifest, force, force, |m| {
        Manifest::new(
            m,
            &c.profile.model,
            (Path::new(out), profile_text.as_bytes()),
            Some((Path::new(&signoff_path), &c.signoff)),
            report_path.map(|r| (Path::new(r), report_text.as_bytes())),
        )
    })?;
    if !a.switch("quiet") {
        print!("{}", c.report);
    }
    // A capture of a bus RoboDR cannot read must not pass as a quiet robot.
    for w in c
        .report
        .warnings
        .iter()
        .filter(|w| w.code == "unsupported_middleware")
    {
        eprintln!("robodr-commission: WARNING: {}", w.message);
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
    key: Option<&robodr_signer::KeySigner>,
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
        attestation: None,
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
            "hard-cap-torque",
            "hard-cap-kp",
            "hard-cap-position-step",
            "platform",
            "unit-id",
            "profile-version",
            "parent",
            "sign-key",
            "trusted-keys",
            "locked-at",
            "operators",
            "motion-quorum",
        ],
        &["force", "no-manifest"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let caps = hard_caps(&a)?;
    let input = a.required("in")?;
    let out = a.required("out")?;
    let signoff_path = a.required("signoff")?;
    let operators_path = a.required("operators")?;
    let min_quorum = match a.u64_opt("motion-quorum")? {
        None => 1,
        Some(0) => return Err("--motion-quorum must be at least 1".to_string().into()),
        Some(n) => usize::try_from(n).map_err(|_| "--motion-quorum is too large".to_string())?,
    };
    let sig_out = sig_path_for(Path::new(out)).display().to_string();
    let signoff_sigs = signoff_sig_path(Path::new(signoff_path))
        .display()
        .to_string();
    let mut inputs = vec![input, signoff_path, operators_path, signoff_sigs.as_str()];
    inputs.extend(a.one("parent")?);
    inputs.extend(a.one("sign-key")?);
    distinct_paths(&[out, sig_out.as_str()], &inputs)?;
    let trust = OperatorTrust::load(Path::new(operators_path))?;
    if min_quorum > trust.operators().len() {
        return Err(format!(
            "--motion-quorum {min_quorum} exceeds the {} operator(s) in {operators_path}",
            trust.operators().len()
        )
        .into());
    }
    let policy = OperatorPolicy {
        trust: &trust,
        min_motion_quorum: min_quorum,
    };
    let key = a
        .one("sign-key")?
        .map(|k| robodr_signer::load(Path::new(k)))
        .transpose()?;
    let draft = read_text(input, MAX_PROFILE_BYTES)?;
    // An unreadable draft is an input error (exit 2), not a refusal.
    let parsed = parse_profile_text(&draft).map_err(|e| format!("{input}: {e}"))?;
    let signoff_text = read_text(signoff_path, MAX_SIGNOFF_BYTES)?;
    let signoff: Signoff = serde_json::from_str(&signoff_text)
        .map_err(|e| format!("{signoff_path}: not a sign-off file: {e}"))?;
    let sigs = load_signoff_sigs(&signoff_sigs)?;
    // Flag / parent errors are usage errors (exit 2) and are reported
    // before the lock decision; the operator name is checked by the lock
    // itself (a refusal, exit 1), so a placeholder stands in for it here.
    lock_metadata(&a, &parsed, "pending-sign-off")?;
    let manifest_refusals = if a.switch("no-manifest") {
        eprintln!("warning: --no-manifest: not checking {input} against its output manifest");
        Vec::new()
    } else {
        verify_manifest(Path::new(input), draft.as_bytes(), Some(&signoff))
    };
    let result = lock_signed_draft(&draft, &signoff_text, sigs.as_ref(), &policy, &caps);
    let result = match (result, manifest_refusals.is_empty()) {
        (Ok(v), true) => Ok(v),
        (Ok(_), false) => Err(manifest_refusals),
        (Err(mut r), _) => {
            r.splice(0..0, manifest_refusals);
            Err(r)
        }
    };
    match result {
        Ok((mut locked, signoff)) => {
            let mut meta = lock_metadata(&a, &parsed, &signoff.operator)?;
            let sigs = sigs.as_ref().ok_or_else(|| {
                "internal: lock succeeded without operator signatures".to_string()
            })?;
            meta.attestation = Some(attestation_for(&signoff_text, sigs));
            locked.metadata = Some(meta);
            // The unit will verify exactly this; never write a profile that
            // would fail it.
            verify_attestation(&locked, &trust)
                .map_err(|e| format!("internal: the embedded attestation does not verify: {e}"))?;
            if let Err(errs) = locked.validate() {
                let list: Vec<String> = errs.iter().map(ToString::to_string).collect();
                return Err(format!("locked profile fails validation: {}", list.join("; ")).into());
            }
            let (text, sig) = seal_and_sign(&locked, key.as_ref())?;
            write_locked(out, &text, sig.as_deref(), a.switch("force"))?;
            let m = locked.metadata.as_ref().expect("set above");
            eprintln!(
                "locked profile {} -> {out} (sealed; profile_version {}, platform {}; signed off \
                 by {:?}, operator signatures embedded as attestation; digest {})",
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
    let a = Args::parse(
        argv,
        &["profile", "sign-key", "operators"],
        &["force", "allow-unattested"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let profile = a.required("profile")?;
    let key_path = a.required("sign-key")?;
    let operators = a.one("operators")?;
    let sig_out = sig_path_for(Path::new(profile)).display().to_string();
    let mut inputs = vec![profile, key_path];
    inputs.extend(operators);
    distinct_paths(&[sig_out.as_str()], &inputs)?;
    let key = robodr_signer::load(Path::new(key_path))?;
    let text = read_text(profile, MAX_PROFILE_BYTES)?;
    let p = parse_profile_text(&text).map_err(|e| format!("{profile}: {e}"))?;
    if !p.locked {
        return Err(format!("{profile}: not locked (drafts are not signed)").into());
    }
    let Some(meta) = p.metadata.as_ref() else {
        return Err(format!(
            "{profile}: legacy locked profile without metadata; use `migrate-legacy`"
        )
        .into());
    };
    // Never put a profile key's signature on a profile without operator
    // sign-off evidence, unless explicitly asked (units with trust roots
    // refuse it anyway).
    match (&meta.attestation, a.switch("allow-unattested")) {
        (None, false) => {
            return Err(format!(
                "{profile}: carries no operator sign-off attestation (not produced by `lock`): \
                 refusing to sign; units that require attestation (the default with trust \
                 roots) refuse it. Pass --allow-unattested to sign it anyway"
            )
            .into())
        }
        (None, true) => {
            eprintln!("warning: {profile} is unattested: units that require attestation refuse it")
        }
        (Some(_), _) => {}
    }
    if let (Some(_), Some(ops)) = (&meta.attestation, operators) {
        let trust = OperatorTrust::load(Path::new(ops))?;
        let s = verify_attestation(&p, &trust)
            .map_err(|e| format!("{profile}: refusing to sign: {e}"))?;
        eprintln!(
            "attestation verified against {ops}: operator {:?}, signers {:?}",
            s.operator, s.signers
        );
    }
    let sig = ProfileSignature::create(text.as_bytes(), &key).map_err(|e| e.to_string())?;
    write_file(&sig_out, &sig.to_text(), a.switch("force"))?;
    eprintln!(
        "signed {profile} ({}) by {} -> {sig_out}",
        sig.profile_digest, sig.key_id
    );
    Ok(())
}

/// Sign a Motion Firewall configuration for the locked profile it belongs
/// to (sales-readiness T11): `<firewall>.sig`, bound to the profile's
/// digest (`trust::firewall_signed_bytes`). An enforcing
/// `robodr-firewall-gw` refuses a firewall file without a valid one from
/// the key that signed its profile.
fn cmd_sign_firewall(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["firewall", "profile", "sign-key"], &["force"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let firewall = a.required("firewall")?;
    let profile = a.required("profile")?;
    let key_path = a.required("sign-key")?;
    let sig_out = sig_path_for(Path::new(firewall)).display().to_string();
    distinct_paths(&[sig_out.as_str()], &[firewall, profile, key_path])?;
    let key = robodr_signer::load(Path::new(key_path))?;
    let ptext = read_text(profile, MAX_PROFILE_BYTES)?;
    let p = parse_profile_text(&ptext).map_err(|e| format!("{profile}: {e}"))?;
    if !p.locked {
        return Err(
            format!("{profile}: not locked (an envelope is signed for a locked profile)").into(),
        );
    }
    let ftext = read_text(firewall, MAX_PROFILE_BYTES)?;
    robodr_firewall::FirewallConfig::from_json(&ftext)
        .map_err(|e| format!("{firewall}: not a valid firewall configuration: {e:?}"))?;
    let pdigest = file_digest(ptext.as_bytes());
    let signed = robodr_commission::trust::firewall_signed_bytes(&pdigest, ftext.as_bytes());
    let sig = ProfileSignature::create_for(SigKind::FirewallConfig, &signed, &key)
        .map_err(|e| e.to_string())?;
    write_file(&sig_out, &sig.to_text(), a.switch("force"))?;
    eprintln!(
        "signed {firewall} for {profile} ({pdigest}) by {} -> {sig_out}",
        sig.key_id
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
    signer_fingerprint: Option<String>,
    attested_by: Option<Vec<String>>,
    rollback: Option<String>,
    revocation_serial: Option<u64>,
    refused: Option<String>,
    /// `bound_config` of the trusted profile (role -> digest).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    bound_config: BTreeMap<String, String>,
    /// Accepted under a lab-only (`poc-init`) trust file.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    lab_only: bool,
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
        signer_fingerprint: None,
        attested_by: None,
        rollback: None,
        revocation_serial: None,
        refused: None,
        bound_config: BTreeMap::new(),
        lab_only: false,
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
            r.signer_fingerprint = v.signer_fingerprint.clone();
            r.attested_by = v
                .attestation
                .as_ref()
                .map(|s| s.signers.iter().cloned().collect());
            r.rollback = acc.decision.map(|d| format!("{d:?}"));
            r.revocation_serial = acc.record.as_ref().and_then(|s| s.revocation_serial);
            r.trusted = v.profile.locked;
            r.bound_config = v.profile.bound_config.clone();
            r.lab_only = v.lab_only;
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
             {:?}{}, digest {}{}{}",
            r.model.as_deref().unwrap_or_default(),
            r.profile_version.unwrap_or_default(),
            r.platform.as_deref().unwrap_or_default(),
            r.unit_id,
            r.signed_by.as_deref().unwrap_or_default(),
            r.signer_fingerprint
                .as_deref()
                .map(|f| format!(" ({f})"))
                .unwrap_or_default(),
            r.digest.as_deref().unwrap_or_default(),
            r.rollback
                .as_ref()
                .map(|d| format!(", anti-rollback: {d}"))
                .unwrap_or_default(),
            r.revocation_serial
                .map(|n| format!(", revocation list serial {n}"))
                .unwrap_or_default()
        );
        if let Some(ops) = &r.attested_by {
            println!("  attested by operators {ops:?}");
        }
        for (role, d) in &r.bound_config {
            println!("  binds {role} {d}");
        }
        if r.lab_only {
            println!("  {}", robodr_commission::poc::LAB_ONLY_BANNER);
        }
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
    let fingerprint = key_fingerprint(vk.as_bytes());
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
        "wrote Ed25519 {} key {out} (mode 0600, key id {}, fingerprint {}), its public key \
         {pub_out} and {} {trust_out}; keep the key off the robot, install the {} on it",
        if roots {
            "trust-root"
        } else {
            "profile signing"
        },
        kf.key_id,
        fingerprint,
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
        &["out", "pub", "min-profile-version", "sign-key", "operators"],
        &[
            "force",
            "roots",
            "require-attestation",
            "no-require-attestation",
        ],
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
    let operators_path = a.one("operators")?;
    let roots = a.switch("roots");
    let require_attestation = match (
        a.switch("require-attestation"),
        a.switch("no-require-attestation"),
    ) {
        (true, true) => {
            return Err(
                "--require-attestation and --no-require-attestation are exclusive"
                    .to_string()
                    .into(),
            )
        }
        (true, false) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
    };
    if roots
        && (floor.is_some()
            || sign_key.is_some()
            || operators_path.is_some()
            || require_attestation.is_some())
    {
        return Err(
            "--roots writes a trust-roots file; --min-profile-version / --sign-key / --operators \
             / --(no-)require-attestation belong to a profile trust file"
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
    inputs.extend(operators_path);
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
    let operators = operators_path
        .map(|p| OperatorTrust::load(Path::new(p)))
        .transpose()?;
    if require_attestation == Some(true) && operators.is_none() {
        return Err("--require-attestation needs --operators operators.json"
            .to_string()
            .into());
    }
    let text = trust_file_text_with(
        &keys,
        &TrustFileOptions {
            min_profile_version: floor,
            require_attestation,
            operators: operators.as_ref(),
            lab_only: false,
        },
    );
    // Check what a unit will check (without roots here: the root signature
    // is checked below by construction).
    if let Err(e) = robodr_commission::trust::parse_trust_file(&text, None, "(new)", None) {
        let e = e.to_string();
        if !(floor.is_some() && e.contains("min_profile_version is set")) {
            return Err(e.into());
        }
    }
    match sign_key {
        None => {
            write_file(out, &text, a.switch("force"))?;
            eprintln!(
                "wrote trust file {out} with {} key(s){}; install it on the robot. It is NOT \
                 signed: a unit with trust roots configured refuses it (sign it with --sign-key \
                 ROOT.key)",
                keys.len(),
                operators
                    .as_ref()
                    .map(|o| format!(
                        ", {} operator(s), motion_quorum {}",
                        o.operators().len(),
                        o.motion_quorum()
                    ))
                    .unwrap_or_default()
            );
        }
        Some(k) => {
            let root = robodr_signer::load(Path::new(k))?;
            if keys.iter().any(|p| p.as_bytes() == &root.public_key()) {
                return Err(format!(
                    "{k}: the trust root must not be one of the profile keys it signs for"
                )
                .into());
            }
            if operators
                .as_ref()
                .is_some_and(|o| o.public_keys().any(|p| p.as_bytes() == &root.public_key()))
            {
                return Err(format!("{k}: the trust root must not be an operator key").into());
            }
            let sig = ProfileSignature::create_for(SigKind::TrustFile, text.as_bytes(), &root)
                .map_err(|e| e.to_string())?;
            write_files(
                &[(out, &text), (&sig_out, &sig.to_text())],
                a.switch("force"),
            )?;
            eprintln!(
                "wrote trust file {out} with {} key(s){}{} and its root signature {sig_out} (by \
                 {}); install both on the robot",
                keys.len(),
                floor
                    .map(|f| format!(", min_profile_version {f}"))
                    .unwrap_or_default(),
                operators
                    .as_ref()
                    .map(|o| format!(
                        ", {} operator(s), motion_quorum {}",
                        o.operators().len(),
                        o.motion_quorum()
                    ))
                    .unwrap_or_default(),
                sig.key_id
            );
            if operators.is_none() && require_attestation != Some(false) {
                eprintln!(
                    "warning: no --operators: with trust roots configured a unit requires \
                     operator attestation by default and refuses this trust file; add \
                     --operators operators.json (or --no-require-attestation)"
                );
            }
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
            "revoke-key",
            "key-fingerprint",
            "platform",
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
    let key_pubs: Vec<&str> = a.all("revoke-key").iter().map(String::as_str).collect();
    inputs.extend(key_pubs.iter().copied());
    distinct_paths(&[out], &inputs)?;
    precheck_outputs(&[out], a.switch("force"))?;
    let root = robodr_signer::load(Path::new(key_path))?;
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
    let platform = match (a.one("platform")?, &base) {
        (Some(p), Some(b)) if p != b.platform => {
            return Err(format!(
                "--platform {p:?} differs from the base list's platform {:?}",
                b.platform
            )
            .into())
        }
        (Some(p), _) => p.to_string(),
        (None, Some(b)) => b.platform.clone(),
        (None, None) => {
            return Err("--platform is required (the list is bound to one platform)"
                .to_string()
                .into())
        }
    };
    let mut keys: Vec<String> = base
        .as_ref()
        .map(|l| l.revoked_keys.clone())
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
    let pub_paths: Vec<&Path> = key_pubs.iter().map(|p| Path::new(*p)).collect();
    for vk in verifying_keys_from_public_files(&pub_paths)? {
        keys.push(key_fingerprint(vk.as_bytes()));
    }
    for f in a.all("key-fingerprint") {
        validate_rollback_flag(f).map_err(|_| {
            format!(
                "--key-fingerprint {f:?} must be sha256:<64 lower-case hex> (keygen and \
                 verify-profile print it)"
            )
        })?;
        keys.push(f.clone());
    }
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
    let list = RevocationList::create(serial, issued_at, &platform, digests, keys, &root)?;
    write_file(out, &list.to_text(), a.switch("force"))?;
    eprintln!(
        "wrote revocation list {out}: platform {}, serial {}, {} revoked digest(s), {} revoked \
         key(s), signed by {}, digest {}; install it on every robot of the platform \
         (profile_trust.revocation_list)",
        list.platform,
        list.serial,
        list.revoked_digests.len(),
        list.revoked_keys.len(),
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
    platform: Option<String>,
    revoked_digests: Vec<String>,
    revoked_keys: Vec<String>,
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
        platform: None,
        revoked_digests: Vec::new(),
        revoked_keys: Vec::new(),
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
            r.platform = Some(l.platform.clone());
            r.revoked_digests = l.revoked_digests.clone();
            r.revoked_keys = l.revoked_keys.clone();
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
            "VALID {path}: platform {:?}, serial {}, issued_at {}, {} revoked digest(s), {} \
             revoked key(s), signed by {:?}, digest {}",
            r.platform.as_deref().unwrap_or_default(),
            r.serial.unwrap_or_default(),
            r.issued_at.unwrap_or_default(),
            r.revoked_digests.len(),
            r.revoked_keys.len(),
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
    let key = robodr_signer::load(Path::new(key_path))?;
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
        attestation: None,
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
    eprintln!(
        "warning: a migrated profile carries no operator sign-off attestation: units that \
         require attestation (the default with trust roots) refuse it; re-commission it \
         (learn/signoff/lock) for those"
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
    let a = Args::parse(
        argv,
        &["profile", "events", "pcap", "unitree-legacy-port"],
        &["json", "unitree-legacy"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let profile_path = a.required("profile")?;
    let profile = load_valid_profile(profile_path)?;
    if !profile.locked {
        // A draft is only meaningful with the output set it was written
        // with: refuse a torn or mixed-up set.
        let text = read_text(profile_path, MAX_PROFILE_BYTES)?;
        let mut why = verify_manifest(Path::new(profile_path), text.as_bytes(), None);
        if matches!(why.as_slice(), [LockRefusal::ManifestMissing { .. }]) {
            eprintln!(
                "note: draft {profile_path} has no output manifest (merged, hand-written or \
                 older draft): companion files not checked"
            );
            why.clear();
        }
        if !why.is_empty() {
            let list: Vec<String> = why.iter().map(|w| format!("  - {w}")).collect();
            return Err(format!(
                "{profile_path}: draft does not match its output manifest:\n{}",
                list.join("\n")
            )
            .into());
        }
    }
    let inputs = a.inputs()?;
    let input_opts = a.input_options()?;
    let mut checker = Checker::new(&profile);
    for spec in &inputs {
        let mut src = input::open_with_options(spec, &input_opts).map_err(|e| e.to_string())?;
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
    let a = Args::parse(
        argv,
        &["in", "out", "signoff", "sign-key", "operators"],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    if a.one("sign-key")?.is_some() {
        return cmd_signoff_sign(&a);
    }
    for f in ["signoff", "operators"] {
        if a.one(f)?.is_some() {
            return Err(format!("--{f} is only valid with --sign-key").into());
        }
    }
    let input = a.required("in")?;
    let out = a.required("out")?;
    let manifest = manifest_path_for(Path::new(input)).display().to_string();
    distinct_paths(&[out, manifest.as_str()], &[input])?;
    let force = a.switch("force");
    precheck_outputs(&[out], force)?;
    let text = read_text(input, MAX_PROFILE_BYTES)?;
    let p = parse_profile_text(&text).map_err(|e| format!("{input}: {e}"))?;
    if p.locked {
        return Err(format!("{input}: already locked").into());
    }
    // A manifest that no longer matches the draft (it was edited after
    // learn) describes an output set that is gone: replacing it needs no
    // --force. One that still matches is learn's and is kept unless --force.
    let stale = read_regular_file(Path::new(&manifest), MAX_SIGNOFF_BYTES)
        .ok()
        .and_then(|t| Manifest::parse(&t).ok())
        .is_some_and(|m| m.draft.sha256 != sha256_hex(text.as_bytes()));
    let replace_manifest = force || stale;
    precheck_outputs(&[manifest.as_str()], replace_manifest)?;
    // Bound to the draft's canonical content (`draft_digest`), not to the
    // bytes on disk (a hand-edited draft may differ in layout): that is
    // what the unit verifies the attestation of the locked profile against.
    let s = Signoff::for_profile(&p);
    let list = json(&s)?;
    publish_with_manifest(
        &[(out, list.as_str())],
        &manifest,
        force,
        replace_manifest,
        |m| {
            Manifest::new(
                m,
                &p.model,
                (Path::new(input), text.as_bytes()),
                Some((Path::new(out), &s)),
                None,
            )
        },
    )?;
    eprintln!(
        "wrote conservative sign-off list {out} ({} item(s)) and manifest {manifest}: review \
         each item, set \"confirmed\": true, fill \"operator\", then sign it \
         (`robodr-commission signoff --signoff {out} --sign-key <operator.key>`)",
        s.items.len()
    );
    Ok(())
}

/// `signoff --signoff S --sign-key K`: the operator signs the confirmed
/// list (exact bytes) and the signature is added to `S.sig`.
fn cmd_signoff_sign(a: &Args) -> Outcome {
    if let Some(o) = a.one("out")? {
        return Err(format!(
            "--out {o:?} is not used with --sign-key (the signature goes to <signoff>.sig)"
        )
        .into());
    }
    let so_path = a.required("signoff")?;
    let key_path = a.required("sign-key")?;
    let sig_out = signoff_sig_path(Path::new(so_path)).display().to_string();
    let mut inputs = vec![so_path, key_path];
    inputs.extend(a.one("in")?);
    inputs.extend(a.one("operators")?);
    distinct_paths(&[sig_out.as_str()], &inputs)?;
    let key = robodr_signer::load(Path::new(key_path))?;
    let key_id = robodr_blackbox::Signer::key_id(&key).to_string();
    let text = read_text(so_path, MAX_SIGNOFF_BYTES)?;
    let so: Signoff =
        serde_json::from_str(&text).map_err(|e| format!("{so_path}: not a sign-off file: {e}"))?;
    // Never sign what lock would refuse for content reasons.
    let mut why: Vec<String> = Vec::new();
    if let Err(e) = so.check_shape() {
        why.push(e);
    }
    if !so.items_intact() {
        why.push(
            "items were deleted, added or reworded (items_sha256 differs); refusing to sign".into(),
        );
    }
    if so.operator.trim().is_empty() {
        why.push("no operator name (fill in \"operator\")".into());
    }
    for i in so.unconfirmed() {
        why.push(format!("not confirmed: {}", i.id));
    }
    if let Some(input) = a.one("in")? {
        let draft = read_text(input, MAX_PROFILE_BYTES)?;
        let p = parse_profile_text(&draft).map_err(|e| format!("{input}: {e}"))?;
        if so.profile_sha256 != sha256_hex(draft.as_bytes())
            && so.profile_sha256 != draft_digest(&p)
        {
            why.push(format!(
                "the sign-off does not belong to {input} (profile_sha256 differs)"
            ));
        }
        for req in required_items(&p) {
            if !so.items.iter().any(|i| satisfies(i, &req)) {
                why.push(format!(
                    "required item missing for {}: {}",
                    req.subject, req.why
                ));
            }
        }
    }
    let mut signer_name = None;
    if let Some(op) = a.one("operators")? {
        let trust = OperatorTrust::load(Path::new(op))?;
        match trust.operator_of(&key_id) {
            None => why.push(format!(
                "key {key_id:?} is not in the operators trust list {op}"
            )),
            Some(name) => signer_name = Some(name.to_string()),
        }
    }
    if !why.is_empty() {
        eprintln!("refusing to sign {so_path}:");
        for w in why {
            eprintln!("  - {w}");
        }
        return Err(Failure::Negative);
    }
    let force = a.switch("force");
    let existing = load_signoff_sigs(&sig_out)?;
    let existed = existing.is_some();
    let mut sigs = match existing {
        Some(s) if s.signoff_digest == signoff_file_digest(text.as_bytes()) => s,
        Some(s) if force => {
            eprintln!(
                "warning: discarding {} signature(s) in {sig_out} made over an earlier version \
                 of the list",
                s.signatures.len()
            );
            SignoffSignatures::new(text.as_bytes())
        }
        Some(_) => {
            return Err(format!(
                "{sig_out}: its signatures are over an earlier version of {so_path} (the list \
                 changed after it was signed, so they are void); pass --force to discard them \
                 and start over"
            )
            .into())
        }
        None => SignoffSignatures::new(text.as_bytes()),
    };
    sigs.add(text.as_bytes(), &key)?;
    // Adding to the signature file is the point of this command, so an
    // existing one (validated above) is replaced atomically.
    write_file(&sig_out, &sigs.to_text(), existed)?;
    eprintln!(
        "signed {so_path} as key {key_id}{} -> {sig_out} ({} signature(s) now; operator named \
         in the list: {:?})",
        signer_name
            .map(|n| format!(" (operator {n:?})"))
            .unwrap_or_default(),
        sigs.signatures.len(),
        so.operator
    );
    Ok(())
}

/// `operators`: build the operators trust list from public key files.
fn cmd_operators(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["out", "operator", "motion-quorum"], &["force"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let out = a.required("out")?;
    let specs = a.all("operator");
    if specs.is_empty() {
        return Err("--operator NAME=KEY.pub is required (one per operator key)"
            .to_string()
            .into());
    }
    let mut entries = Vec::new();
    let mut pubs: Vec<&str> = Vec::new();
    for spec in specs {
        let (name, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--operator {spec:?}: expected NAME=KEY.pub"))?;
        let keys = verifying_keys_from_public_files(&[Path::new(path)])?;
        let vk = keys
            .into_iter()
            .next()
            .ok_or_else(|| format!("{path}: no key"))?;
        entries.push((name.to_string(), vk));
        pubs.push(path);
    }
    distinct_paths(&[out], &pubs)?;
    let quorum = match a.u64_opt("motion-quorum")? {
        None => 1,
        Some(n) => usize::try_from(n).map_err(|_| "--motion-quorum is too large".to_string())?,
    };
    let trust = OperatorTrust::new(entries, quorum)?;
    write_file(out, &trust.to_text(), a.switch("force"))?;
    eprintln!(
        "wrote operators trust list {out}: {} key(s), {} operator(s), motion quorum {}; keep \
         it where only the security officer can write it (lock refuses it if group/others can)",
        specs.len(),
        trust.operators().len(),
        trust.motion_quorum()
    );
    Ok(())
}

fn cmd_merge(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "out",
            "hard-cap-linear",
            "hard-cap-joint",
            "hard-cap-torque",
            "hard-cap-kp",
            "hard-cap-position-step",
        ],
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
