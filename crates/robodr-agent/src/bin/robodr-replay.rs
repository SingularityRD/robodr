//! `robodr-replay`: run RobotEvent JSONL through the RoboDR decision chain
//! offline, record evidence in a black box, write findings, and verify.
//!
//! Exit codes: 0 success and everything verified; 1 the black box or an
//! evidence link failed verification; 2 usage, input, config or I/O error
//! (including an argument that is not valid UTF-8); 3 (`run` only) the
//! evidence that was written verifies, but findings were lost (they failed
//! OCSF validation and were not written), so the findings output is
//! incomplete. 1 takes precedence over 3. Argument parsing is std-only by
//! design.
//!
//! The black-box key is read only from a key file (`--key-file`, as written
//! by `robodr-blackbox keygen`: Ed25519; a legacy HMAC key is refused
//! unless `--allow-hmac`),
//! checked by `robodr_blackbox::KeyFile::load` (regular file, no symlink;
//! a file with secret material must have no group/other bits and be owned
//! by this user or root); its key id comes from the file. `run` needs the
//! secret key file; `verify` also accepts the public `.pub` file.
//! Keys are never accepted on the command line: argv is readable by every
//! process through /proc.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// daemon (systemd restarts it; docs/OPERATIONS.md, "Crashes and restarts").
// Non-test code has no unwrap / expect / panic!-family call; slice indexing
// and arithmetic are left to review and fuzzing (fuzz/README.md).
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

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use robodr_agent::replay::{self, ReplayOptions};
use robodr_motion::{FeedbackSource, MonitorConfig};

const USAGE: &str = "\
robodr-replay: offline RoboDR decision chain (event -> deviation -> plan -> black box -> finding)

USAGE:
  robodr-replay [run] --events run.jsonl --profile profile.json --policy policy.json
                --blackbox DIR --key-file FILE --robot-id ID
                [--out findings.jsonl] [--outcomes outcomes.jsonl]
                [--safety-state STATE] [--control autonomous|teleop|manual]
                [--phase parked|transit|task|takeoff|landing|unknown]
                [--connectivity connected|degraded|disconnected] [--no-operator]
                [--site NAME] [--model NAME] [--boot-id ID]
                [--trusted-keys trust.json] [--profile-state FILE]
                [--allow-profile-rollback sha256:HEX]
                [--trust-roots roots.json [--revocations revocations.json
                 [--revocations-required]]]
                [--start-ms EPOCH_MS] [--step-ms MS]
                [--firewall] [--firewall-allow CHANNEL=GUID[,GUID...]]...
                [--firewall-max-angular CHANNEL=RAD_PER_S]...
                [--monitor | --monitor-config FILE] [--feedback-source CHANNEL=SOURCE]...
                [--record-all-events] [--partitions N] [--log-plans] [--allow-hmac]
  robodr-replay verify --blackbox DIR --key-file FILE
                [--robot-id ID] [--findings findings.jsonl] [--allow-hmac]
  robodr-replay --help | --version

  STATE:  idle | moving_slow | moving_fast | collaborative_human_nearby |
          estop_active | safe_state_active | unknown (default unknown)
  SOURCE: wheel_odometry | imu | joint_state | gnss | other
  Findings go to stdout unless --out is given; the summary goes to stderr.
  --firewall needs --firewall-max-angular for every Twist channel of the
  profile (the OEM's yaw-rate bound; the profile has none).
  --key-file is a robodr-blackbox key file (create one with
  `robodr-blackbox keygen --out FILE`: ed25519 secret FILE + public FILE.pub).
  run needs the secret file (mode 0600 or stricter, own user or root);
  verify also accepts the public FILE.pub (any mode). Its key id is used.
  Keys are never taken on the command line. Legacy hmac-sha256 key files
  are symmetric (whoever verifies can forge) and refused unless
  --allow-hmac is given (then a warning is printed).
  --blackbox must be absent or empty (a replay starts a fresh chain).
  A locked profile is enforced only with a valid <profile>.sig from a key in
  --trusted-keys (robodr-profile-trust/v1); otherwise the replay is
  observe-only and its first finding is robot.ros2.profile_refused. The
  profile version in findings comes from the signed profile's metadata.
  --profile-state enables anti-rollback (off by default: replays of old
  recordings legitimately use old profiles).
  --trust-roots (robodr-trust-roots/v1) verifies a signed min_profile_version
  in the trust file and the signed revocation list given by --revocations
  (robodr-profile-revocations/v1): a revoked profile digest or signing key
  is refused. A missing list is allowed unless --revocations-required.
  A replay never acts: --log-plans only prints what would have been requested.

EXIT: 0 ok and verified, 1 verification failed, 2 error,
      3 (run) evidence verified but findings were lost (output incomplete).
";

const VALUED: &[&str] = &[
    "events",
    "profile",
    "policy",
    "blackbox",
    "key-file",
    "robot-id",
    "out",
    "outcomes",
    "safety-state",
    "control",
    "phase",
    "connectivity",
    "site",
    "model",
    "boot-id",
    "trusted-keys",
    "profile-state",
    "allow-profile-rollback",
    "trust-roots",
    "revocations",
    "start-ms",
    "step-ms",
    "firewall-allow",
    "firewall-max-angular",
    "monitor-config",
    "feedback-source",
    "partitions",
    "findings",
];
const SWITCHES: &[&str] = &[
    "firewall",
    "monitor",
    "record-all-events",
    "log-plans",
    "no-operator",
    "revocations-required",
    "allow-hmac",
    "help",
];

/// Options that no longer exist, with the reason (reported as usage errors).
const REMOVED: &[(&str, &str)] = &[
    (
        "key-hex",
        "--key-hex was removed: argv is visible to every process; use --key-file \
         (create one with `robodr-blackbox keygen --out FILE`)",
    ),
    (
        "key-id",
        "--key-id was removed: the key id comes from the --key-file",
    ),
    (
        "profile-version",
        "--profile-version was removed: the version is taken from the signed profile's \
         metadata (`robodr-commission lock --profile-version N`); pass --trusted-keys so the \
         profile is verified",
    ),
];

/// Exit code of a `run` whose evidence verifies but that lost findings.
const EXIT_FINDINGS_LOST: u8 = 3;

struct Args {
    opts: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
}

impl Args {
    fn parse(argv: &[String]) -> Result<Self, String> {
        let mut a = Args {
            opts: BTreeMap::new(),
            switches: Vec::new(),
        };
        let mut it = argv.iter();
        while let Some(arg) = it.next() {
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument {arg:?}"));
            };
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };
            if SWITCHES.contains(&name) {
                if inline.is_some() {
                    return Err(format!("--{name} takes no value"));
                }
                a.switches.push(name.to_string());
            } else if VALUED.contains(&name) {
                let v = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("--{name} needs a value"))?,
                };
                a.opts.entry(name.to_string()).or_default().push(v);
            } else if let Some((_, why)) = REMOVED.iter().find(|(n, _)| *n == name) {
                return Err((*why).to_string());
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(a)
    }

    fn one(&self, k: &str) -> Result<Option<&str>, String> {
        match self.opts.get(k).map(Vec::as_slice) {
            None | Some([]) => Ok(None),
            Some([v]) => Ok(Some(v)),
            Some(_) => Err(format!("--{k} given more than once")),
        }
    }

    fn req(&self, k: &str) -> Result<&str, String> {
        self.one(k)?.ok_or_else(|| format!("--{k} is required"))
    }

    fn all(&self, k: &str) -> &[String] {
        self.opts.get(k).map_or(&[], Vec::as_slice)
    }

    fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }
}

/// Parse a snake_case enum through its serde representation.
fn parse_enum<T: serde::de::DeserializeOwned>(what: &str, v: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(v.to_string()))
        .map_err(|_| format!("invalid {what} {v:?}"))
}

fn parse_u64(what: &str, v: &str) -> Result<u64, String> {
    v.parse::<u64>()
        .map_err(|_| format!("invalid {what} {v:?}"))
}

/// Load the black-box signing key from `--key-file` (secret key file,
/// permission-checked; Ed25519, or HMAC with `--allow-hmac`). Returns the key material, the key
/// id from the file and the algorithm.
fn key_from(a: &Args) -> Result<(Vec<u8>, String, String), String> {
    let p = a.req("key-file")?;
    let kf = robodr_blackbox::KeyFile::load_secret(p.as_ref()).map_err(|e| format!("{p}: {e}"))?;
    // Refuses unknown algorithms and re-checks the key length.
    kf.signer().map_err(|e| format!("{p}: {e}"))?;
    hmac_policy(a, p, &kf)?;
    Ok((
        kf.secret().to_vec(),
        kf.key_id.clone(),
        kf.algorithm.clone(),
    ))
}

/// Refuse a legacy HMAC key unless `--allow-hmac`; warn when allowed.
fn hmac_policy(a: &Args, p: &str, kf: &robodr_blackbox::KeyFile) -> Result<(), String> {
    kf.check_hmac_policy(a.has("allow-hmac"))
        .map_err(|e| format!("{p}: {e}"))?;
    if kf.is_symmetric() {
        eprintln!(
            "robodr-replay: warning: {p} is an hmac-sha256 key (symmetric placeholder, \
             allowed by --allow-hmac; use `robodr-blackbox keygen` for ed25519)"
        );
    }
    Ok(())
}

/// The verifier for `verify`: a secret or public key file.
fn verifier_from(a: &Args) -> Result<Box<dyn robodr_blackbox::Verifier>, String> {
    let p = a.req("key-file")?;
    let kf = robodr_blackbox::KeyFile::load(p.as_ref()).map_err(|e| format!("{p}: {e}"))?;
    hmac_policy(a, p, &kf)?;
    kf.verifier().map_err(|e| format!("{p}: {e}"))
}

fn kv(what: &str, v: &str) -> Result<(String, String), String> {
    v.split_once('=')
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("{what} must be CHANNEL=VALUE, got {v:?}"))
}

fn options(a: &Args) -> Result<ReplayOptions, String> {
    let (events, profile, policy, blackbox) = (
        a.req("events")?,
        a.req("profile")?,
        a.req("policy")?,
        a.req("blackbox")?,
    );
    let (key, key_id, algorithm) = key_from(a)?;
    let mut o = ReplayOptions::new(events, profile, policy, blackbox, key, a.req("robot-id")?);
    o.key_id = Some(key_id);
    o.key_algorithm = algorithm;
    if let Some(v) = a.one("safety-state")? {
        o.safety = parse_enum("safety state", v)?;
    }
    if let Some(v) = a.one("control")? {
        o.control = parse_enum("control mode", v)?;
    }
    if let Some(v) = a.one("phase")? {
        o.phase = parse_enum("mission phase", v)?;
    }
    if let Some(v) = a.one("connectivity")? {
        o.connectivity = parse_enum("connectivity", v)?;
    }
    o.operator_present = !a.has("no-operator");
    if let Some(v) = a.one("site")? {
        o.site = v.into();
    }
    o.model = a.one("model")?.map(str::to_string);
    o.trusted_keys = a.one("trusted-keys")?.map(PathBuf::from);
    o.profile_state = a.one("profile-state")?.map(PathBuf::from);
    o.allow_profile_rollback = a.one("allow-profile-rollback")?.map(str::to_string);
    if let Some(f) = &o.allow_profile_rollback {
        robodr_commission::trust::validate_rollback_flag(f)?;
    }
    o.trust_roots = a.one("trust-roots")?.map(PathBuf::from);
    o.revocation_list = a.one("revocations")?.map(PathBuf::from);
    if o.revocation_list.is_some() && o.trust_roots.is_none() {
        return Err("--revocations needs --trust-roots (the keys that sign it)".into());
    }
    if a.has("revocations-required") {
        if o.revocation_list.is_none() {
            return Err("--revocations-required needs --revocations".into());
        }
        o.revocation_policy = robodr_commission::trust::RevocationPolicy::Required;
    }
    if let Some(v) = a.one("boot-id")? {
        o.boot_id = v.into();
    }
    if let Some(v) = a.one("start-ms")? {
        o.start_wall_ms = parse_u64("--start-ms", v)?;
    }
    if let Some(v) = a.one("step-ms")? {
        o.step_ns = parse_u64("--step-ms", v)?
            .checked_mul(1_000_000)
            .filter(|n| *n > 0)
            .ok_or("--step-ms must be > 0 and fit in u64 ns")?;
    }
    o.firewall = a.has("firewall")
        || !a.all("firewall-allow").is_empty()
        || !a.all("firewall-max-angular").is_empty();
    for v in a.all("firewall-max-angular") {
        let (ch, rad) = kv("--firewall-max-angular", v)?;
        let rad: f64 = rad
            .parse()
            .ok()
            .filter(|x: &f64| x.is_finite() && *x >= 0.0)
            .ok_or_else(|| {
                format!("--firewall-max-angular {ch}: {rad:?} is not a finite rad/s >= 0")
            })?;
        if o.firewall_max_angular.insert(ch.clone(), rad).is_some() {
            return Err(format!("--firewall-max-angular {ch} given more than once"));
        }
    }
    for v in a.all("firewall-allow") {
        let (ch, guids) = kv("--firewall-allow", v)?;
        o.firewall_allow
            .entry(ch)
            .or_default()
            .extend(guids.split(',').map(str::to_string));
    }
    o.monitor = match (a.has("monitor"), a.one("monitor-config")?) {
        (_, Some(p)) => Some(replay::load_monitor_config(p.as_ref()).map_err(|e| e.to_string())?),
        (true, None) => None,
        (false, None) => None,
    };
    for v in a.all("feedback-source") {
        let (ch, src) = kv("--feedback-source", v)?;
        o.feedback_sources
            .insert(ch, parse_enum::<FeedbackSource>("feedback source", &src)?);
    }
    o.record_all_events = a.has("record-all-events");
    if let Some(v) = a.one("partitions")? {
        o.kafka_partitions = Some(
            u32::try_from(parse_u64("--partitions", v)?).map_err(|_| "--partitions too large")?,
        );
    }
    Ok(o)
}

/// Verdict of a command: exit 0, 1 or [`EXIT_FINDINGS_LOST`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Verified,
    Failed,
    FindingsLost,
}

fn run_cmd(a: &Args) -> Result<Verdict, String> {
    let mut o = options(a)?;
    if a.has("monitor") && o.monitor.is_none() {
        // UGV defaults, correlating the profile's motion channels.
        let profile = replay::load_profile(&o.profile).map_err(|e| e.to_string())?;
        let mut mc = MonitorConfig::ugv(profile.model.clone());
        mc.command_channels = profile.motion_envelopes.keys().cloned().collect();
        o.monitor = Some(mc);
    }
    let mut out: Box<dyn Write> = match a.one("out")? {
        Some(p) => Box::new(BufWriter::new(
            File::create(p).map_err(|e| format!("{p}: {e}"))?,
        )),
        None => Box::new(BufWriter::new(std::io::stdout().lock())),
    };
    let mut outcomes: Option<Box<dyn Write>> = match a.one("outcomes")? {
        Some(p) => Some(Box::new(BufWriter::new(
            File::create(p).map_err(|e| format!("{p}: {e}"))?,
        ))),
        None => None,
    };
    let plan_log: Option<Box<dyn Write>> = a
        .has("log-plans")
        .then(|| Box::new(std::io::stderr()) as Box<dyn Write>);
    let summary = replay::run(
        &o,
        &mut out,
        outcomes.as_mut().map(|w| w as &mut dyn Write),
        plan_log,
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| format!("writing findings: {e}"))?;
    if let Some(w) = outcomes.as_mut() {
        w.flush().map_err(|e| format!("writing outcomes: {e}"))?;
    }

    match &summary.profile_refused {
        Some(why) => eprintln!(
            "profile: NOT enforced (observe-only): {}",
            why.chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect::<String>()
        ),
        None => eprintln!("profile: version {}", summary.profile_version),
    }
    let s = summary.stats;
    eprintln!(
        "replay: {} events, {} deviations {:?}, {} findings written ({} failed), dispositions {:?}",
        summary.events,
        s.deviations,
        summary.by_severity,
        s.findings,
        s.finding_errors,
        summary.by_disposition
    );
    eprintln!(
        "evidence: {} black-box records appended, {} append errors, {} guard violations",
        s.records_appended, s.evidence_errors, s.guard_violations
    );
    if s.faults > 0 {
        eprintln!(
            "agent faults: {} ({} clock regressions, {} wall-clock jumps, {} black-box reopens)",
            s.faults, s.clock_regressions, s.wall_clock_jumps, s.blackbox_reopens
        );
        for f in &summary.faults {
            eprintln!("  {:?}: {}", f.kind, f.detail);
        }
    }
    eprint!("{}", replay::describe_report(&summary.report));
    eprintln!(
        "evidence links: {}/{} resolve to intact signed records",
        summary.links.resolved, summary.links.checked
    );
    for p in &summary.links.problems {
        eprintln!("  {p}");
    }
    let verdict = if !summary.evidence_verified() {
        Verdict::Failed
    } else if summary.findings_lost() > 0 {
        Verdict::FindingsLost
    } else {
        Verdict::Verified
    };
    match verdict {
        Verdict::Verified => eprintln!("VERIFIED: evidence chain intact end to end"),
        Verdict::Failed => eprintln!("NOT VERIFIED"),
        Verdict::FindingsLost => eprintln!(
            "NOT VERIFIED: evidence chain intact, but {} finding(s) were lost \
             (failed validation, not written); the findings output is incomplete",
            summary.findings_lost()
        ),
    }
    Ok(verdict)
}

fn verify_cmd(a: &Args) -> Result<Verdict, String> {
    let dir = PathBuf::from(a.req("blackbox")?);
    let verifier = verifier_from(a)?;
    let findings = a.one("findings")?.map(PathBuf::from);
    let v = replay::verify_with(
        &dir,
        verifier.as_ref(),
        a.one("robot-id")?,
        findings.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    eprint!("{}", replay::describe_report(&v.report));
    if let Some(l) = &v.links {
        eprintln!(
            "evidence links: {}/{} resolve to intact signed records",
            l.resolved, l.checked
        );
        for p in &l.problems {
            eprintln!("  {p}");
        }
    }
    for (line, e) in &v.invalid_findings {
        eprintln!("  findings line {line}: invalid: {e}");
    }
    eprintln!(
        "{}",
        if v.verified() {
            "VERIFIED"
        } else {
            "NOT VERIFIED"
        }
    );
    Ok(if v.verified() {
        Verdict::Verified
    } else {
        Verdict::Failed
    })
}

fn main() -> ExitCode {
    // args_os: std::env::args() panics on an argument that is not valid
    // Unicode; that must be a usage error (exit 2), not an abort.
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(bad) => {
            eprintln!("error: argument {bad:?} is not valid UTF-8\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if argv.len() == 1 && matches!(argv[0].as_str(), "-V" | "--version") {
        println!("robodr-replay {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let (cmd, rest) = match argv.first().map(String::as_str) {
        Some("verify") => ("verify", &argv[1..]),
        Some("run") => ("run", &argv[1..]),
        _ => ("run", &argv[..]),
    };
    let args = match Args::parse(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if args.has("help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if rest.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    let res = if cmd == "verify" {
        verify_cmd(&args)
    } else {
        run_cmd(&args)
    };
    match res {
        Ok(Verdict::Verified) => ExitCode::SUCCESS,
        Ok(Verdict::Failed) => ExitCode::from(1),
        Ok(Verdict::FindingsLost) => ExitCode::from(EXIT_FINDINGS_LOST),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
