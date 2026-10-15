//! `robodr-commission`: observe-mode commissioning CLI.
//!
//! Exit codes: 0 success / clean; 1 negative result (deviations found,
//! profiles differ, lock refused); 2 usage, input or I/O error.
//! Argument parsing is std-only by design (no third-party crates on the
//! robot's build).

use robodr_commission::input::{self, InputSpec};
use robodr_commission::{diff, lock, merge_profiles, to_json, Checker, LearnConfig, Learner};
use robodr_events::profile::Profile;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
robodr-commission: learn, review, lock and verify a RoboDR model profile

USAGE:
  robodr-commission learn --events <run.jsonl> [--events <run2.jsonl> ...]
                          [--model NAME] [--margin 1.1] [--min-samples 30]
                          [--ceiling-linear M_PER_S] [--ceiling-joint RAD_PER_S]
                          --out profile.json [--report report.json] [--quiet]
  robodr-commission lock  --in profile.json --out locked.json
  robodr-commission diff  <old.json> <new.json> [--json]
  robodr-commission check --profile locked.json --events <run.jsonl> [...] [--json]
  robodr-commission merge --out merged.json <a.json> <b.json> [...]

  --pcap <file> is accepted wherever --events is, but is not wired yet.

EXIT: 0 ok/clean, 1 deviations / differences / lock refused, 2 error.
";

/// Max size of a profile file we are willing to load.
const MAX_PROFILE_BYTES: u64 = 64 << 20;

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
                    .map_err(|_| format!("--{name}: {v:?} is not a number"))
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
            return Err("at least one --events <file.jsonl> is required".into());
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
    let argv: Vec<String> = std::env::args().skip(1).collect();
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

/// Write via a temp file + rename so a crash never leaves a half profile.
fn write_file(path: &str, contents: &str) -> Result<(), String> {
    let p = Path::new(path);
    let tmp = {
        let mut name = p
            .file_name()
            .ok_or_else(|| format!("{path}: not a file path"))?
            .to_os_string();
        name.push(format!(".tmp-{}", std::process::id()));
        p.with_file_name(name)
    };
    std::fs::write(&tmp, contents).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{path}: {e}")
    })
}

fn load_profile(path: &str) -> Result<Profile, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut s = String::new();
    f.take(MAX_PROFILE_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{path}: {e}"))?;
    if s.len() as u64 > MAX_PROFILE_BYTES {
        return Err(format!("{path}: larger than {MAX_PROFILE_BYTES} bytes"));
    }
    serde_json::from_str(&s).map_err(|e| format!("{path}: not a profile: {e}"))
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
        ],
        &["quiet"],
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
    if let Some(n) = a.one("min-samples")? {
        cfg.min_samples = n
            .parse()
            .map_err(|_| format!("--min-samples: {n:?} is not a non-negative integer"))?;
    }
    let out = a.required("out")?;
    let inputs = a.inputs()?;

    let mut learner = Learner::new(cfg).map_err(|e| e.to_string())?;
    for spec in &inputs {
        let mut src = input::open(spec).map_err(|e| e.to_string())?;
        learner.ingest(src.as_mut()).map_err(|e| e.to_string())?;
    }
    let c = learner.finish();
    write_file(out, &json(&c.profile)?)?;
    if let Some(r) = a.one("report")? {
        write_file(r, &json(&c.report)?)?;
    }
    if !a.switch("quiet") {
        print!("{}", c.report);
    }
    eprintln!(
        "wrote draft profile {out} (locked: false): {} participants, {} writer topics, \
         {} motion channels; {} anomalies, {} warnings need attention",
        c.profile.participants.len(),
        c.profile.writer_topics.len(),
        c.profile.motion_envelopes.len(),
        c.report.anomalies_total,
        c.report.warn_count()
    );
    Ok(())
}

fn cmd_lock(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["in", "out"], &[])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let input = a.required("in")?;
    let out = a.required("out")?;
    let p = load_profile(input)?;
    match lock(&p) {
        Ok(locked) => {
            write_file(out, &json(&locked)?)?;
            eprintln!("locked profile {} -> {out}", locked.model);
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
    let profile = load_profile(a.required("profile")?)?;
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

fn cmd_merge(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["out"], &[])?;
    let out = a.required("out")?;
    if a.positionals.is_empty() {
        return Err("merge needs at least one profile file".to_string().into());
    }
    let profiles = a
        .positionals
        .iter()
        .map(|p| load_profile(p))
        .collect::<Result<Vec<_>, _>>()?;
    let m = merge_profiles(&profiles).map_err(|e| e.to_string())?;
    write_file(out, &json(&m)?)?;
    eprintln!(
        "merged {} profiles -> {out} (locked: false; review and lock again)",
        profiles.len()
    );
    Ok(())
}
