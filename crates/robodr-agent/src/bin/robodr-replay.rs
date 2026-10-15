//! `robodr-replay`: run RobotEvent JSONL through the RoboDR decision chain
//! offline, record evidence in a black box, write findings, and verify.
//!
//! Exit codes: 0 success and everything verified; 1 the black box or an
//! evidence link failed verification; 2 usage, input, config or I/O error.
//! Argument parsing is std-only by design.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use robodr_agent::replay::{self, ReplayOptions};
use robodr_agent::{Executor, LoggingExecutor};
use robodr_motion::{FeedbackSource, MonitorConfig};

const USAGE: &str = "\
robodr-replay: offline RoboDR decision chain (event -> deviation -> plan -> black box -> finding)

USAGE:
  robodr-replay [run] --events run.jsonl --profile profile.json --policy policy.json
                --blackbox DIR (--key-hex HEX | --key-file FILE) --robot-id ID
                [--out findings.jsonl] [--outcomes outcomes.jsonl]
                [--safety-state STATE] [--control autonomous|teleop|manual]
                [--phase parked|transit|task|takeoff|landing|unknown]
                [--connectivity connected|degraded|disconnected] [--no-operator]
                [--site NAME] [--model NAME] [--profile-version V] [--boot-id ID]
                [--key-id ID] [--start-ms EPOCH_MS] [--step-ms MS]
                [--firewall] [--firewall-allow CHANNEL=GUID[,GUID...]]...
                [--monitor | --monitor-config FILE] [--feedback-source CHANNEL=SOURCE]...
                [--record-all-events] [--partitions N] [--log-plans]
  robodr-replay verify --blackbox DIR (--key-hex HEX | --key-file FILE)
                [--key-id ID] [--robot-id ID] [--findings findings.jsonl]

  STATE:  idle | moving_slow | moving_fast | collaborative_human_nearby |
          estop_active | safe_state_active | unknown (default unknown)
  SOURCE: wheel_odometry | imu | joint_state | gnss | other
  Findings go to stdout unless --out is given; the summary goes to stderr.
  The HMAC key (>= 32 bytes) is a placeholder authenticator (see robodr-blackbox).

EXIT: 0 ok and verified, 1 verification failed, 2 error.
";

const VALUED: &[&str] = &[
    "events",
    "profile",
    "policy",
    "blackbox",
    "key-hex",
    "key-file",
    "key-id",
    "robot-id",
    "out",
    "outcomes",
    "safety-state",
    "control",
    "phase",
    "connectivity",
    "site",
    "model",
    "profile-version",
    "boot-id",
    "start-ms",
    "step-ms",
    "firewall-allow",
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
    "help",
];

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

fn key_from(a: &Args) -> Result<Vec<u8>, String> {
    let hex = match (a.one("key-hex")?, a.one("key-file")?) {
        (Some(h), None) => h.to_string(),
        (None, Some(p)) => std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?,
        (Some(_), Some(_)) => return Err("give --key-hex or --key-file, not both".into()),
        (None, None) => return Err("--key-hex or --key-file is required".into()),
    };
    robodr_blackbox::crypto::from_hex(hex.trim())
        .ok_or_else(|| "black-box key is not valid hex".to_string())
}

fn kv(what: &str, v: &str) -> Result<(String, String), String> {
    v.split_once('=')
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("{what} must be CHANNEL=VALUE, got {v:?}"))
}

fn options(a: &Args) -> Result<ReplayOptions, String> {
    let mut o = ReplayOptions::new(
        a.req("events")?,
        a.req("profile")?,
        a.req("policy")?,
        a.req("blackbox")?,
        key_from(a)?,
        a.req("robot-id")?,
    );
    o.key_id = a.one("key-id")?.map(str::to_string);
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
    if let Some(v) = a.one("profile-version")? {
        o.profile_version = v.into();
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
    o.firewall = a.has("firewall") || !a.all("firewall-allow").is_empty();
    for v in a.all("firewall-allow") {
        let (ch, guids) = kv("--firewall-allow", v)?;
        o.firewall_allow
            .entry(ch)
            .or_default()
            .extend(guids.split(',').map(str::to_string));
    }
    o.monitor = match (a.has("monitor"), a.one("monitor-config")?) {
        (_, Some(p)) => {
            let text = replay::read_capped(p.as_ref()).map_err(|e| e.to_string())?;
            Some(
                serde_json::from_str::<MonitorConfig>(&text)
                    .map_err(|e| format!("{p}: not a monitor config: {e}"))?,
            )
        }
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

fn run_cmd(a: &Args) -> Result<bool, String> {
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
    let executor: Option<Box<dyn Executor>> = a
        .has("log-plans")
        .then(|| Box::new(LoggingExecutor::new(std::io::stderr())) as Box<dyn Executor>);
    let summary = replay::run(
        &o,
        &mut out,
        outcomes.as_mut().map(|w| w as &mut dyn Write),
        executor,
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| format!("writing findings: {e}"))?;
    if let Some(w) = outcomes.as_mut() {
        w.flush().map_err(|e| format!("writing outcomes: {e}"))?;
    }

    let mut by_sev: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_disp: BTreeMap<String, u64> = BTreeMap::new();
    for oc in &summary.outcomes {
        *by_sev
            .entry(format!("{:?}", oc.deviation.severity).to_lowercase())
            .or_default() += 1;
        *by_disp.entry(format!("{:?}", oc.disposition)).or_default() += 1;
    }
    let s = summary.stats;
    eprintln!(
        "replay: {} events, {} deviations {:?}, {} findings written ({} failed), dispositions {:?}",
        summary.events, s.deviations, by_sev, s.findings, s.finding_errors, by_disp
    );
    eprintln!(
        "evidence: {} black-box records appended, {} append errors, {} guard violations",
        s.records_appended, s.evidence_errors, s.guard_violations
    );
    eprint!("{}", replay::describe_report(&summary.report));
    eprintln!(
        "evidence links: {}/{} resolve to intact signed records",
        summary.links.resolved, summary.links.checked
    );
    for p in &summary.links.problems {
        eprintln!("  {p}");
    }
    eprintln!(
        "{}",
        if summary.verified() {
            "VERIFIED: evidence chain intact end to end"
        } else {
            "NOT VERIFIED"
        }
    );
    Ok(summary.verified())
}

fn verify_cmd(a: &Args) -> Result<bool, String> {
    let dir = PathBuf::from(a.req("blackbox")?);
    let key = key_from(a)?;
    let findings = a.one("findings")?.map(PathBuf::from);
    let v = replay::verify(
        &dir,
        &key,
        a.one("key-id")?,
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
    Ok(v.verified())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
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
    if args.has("help") || rest.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(if args.has("help") { 0 } else { 2 });
    }
    let res = if cmd == "verify" {
        verify_cmd(&args)
    } else {
        run_cmd(&args)
    };
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
