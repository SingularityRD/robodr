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

use robodr_commission::input::{self, InputSpec};
use robodr_commission::profile_file::{check_destination, read_regular_file, MAX_PROFILE_BYTES};
use robodr_commission::{
    diff, lock_draft_text_with_caps, merge_profiles_with_caps, parse_profile_text, sealed_text,
    to_json, write_files_atomic, Checker, HardCaps, LearnConfig, Learner, Signoff,
};
use robodr_events::profile::Profile;
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
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]
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

fn cmd_lock(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &["in", "out", "signoff", "hard-cap-linear", "hard-cap-joint"],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let caps = hard_caps(&a)?;
    let input = a.required("in")?;
    let out = a.required("out")?;
    let signoff_path = a.required("signoff")?;
    distinct_paths(&[out], &[input, signoff_path])?;
    let draft = read_text(input, MAX_PROFILE_BYTES)?;
    // An unreadable draft is an input error (exit 2), not a refusal.
    parse_profile_text(&draft).map_err(|e| format!("{input}: {e}"))?;
    let signoff = load_signoff(signoff_path)?;
    match lock_draft_text_with_caps(&draft, &signoff, &caps) {
        Ok(locked) => {
            let text = sealed_text(&locked).map_err(|e| format!("serialise: {e}"))?;
            write_file(out, &text, a.switch("force"))?;
            eprintln!(
                "locked profile {} -> {out} (sealed; signed off by {:?})",
                locked.model, signoff.operator
            );
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
