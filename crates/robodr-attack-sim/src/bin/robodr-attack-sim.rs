//! `robodr-attack-sim`: RoboDR attack scenarios for POCs and demos.
//!
//! Exit codes: 0 success / score passed; 1 score failed; 2 usage, input or
//! guard refusal.

#![forbid(unsafe_code)]

use robodr_attack_sim::guard::{self, Cidr};
use robodr_attack_sim::{
    attack_frames, generate, read_capture, score, write_capture, Params, Scenario,
};
use serde_json::json;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
robodr-attack-sim: RoboDR attack scenarios for proofs of concept and demos

USAGE:
  robodr-attack-sim list [--json]
  robodr-attack-sim pcap  --scenario S[,S...]|all --carrier BASELINE.pcap --out OUT.pcap [PARAMS]
  robodr-attack-sim send  --scenario S --target IP --allow CIDR [--allow CIDR]... --i-understand
                          [--carrier BASELINE.pcap] [PARAMS]
  robodr-attack-sim score --scenario S[,S...]|all --findings SPOOL_DIR|FINDINGS.ndjson
                          [--injected-at-ms UNIX_MS]

  pcap   offline: merge the scenario into a capture of the robot's normal traffic
         (Ethernet pcap/pcapng) and write a pcap for robodr-agentd's pcap_replay.
         Several scenarios run one after another, --stagger seconds apart
         (cmd-vel-envelope rewrites the carrier's commands from --at on).
  send   live: send the scenario's UDP datagrams to one target. Needs --i-understand
         (the robot must be safe-stopped or on a test stand), the target inside an
         --allow CIDR (/16 or narrower), and a private, loopback, link-local or 239/8
         target. Prints the first send time, for score --injected-at-ms.
  score  check the findings a run produced against each scenario's expected rule ids
         (JSON report; exit 1 when one is missing). With --injected-at-ms and a spool
         directory, also the time to detect per rule.

PARAMS:
  --seed N            reproducible randomness (default 24301)
  --at SECS           attack start after the carrier's first frame (default 5)
  --stagger SECS      gap between scenarios in one pcap (default 10)
  --count N           frames of guid-spray / lowcmd-torque (default 3000)
  --rate PPS          frame rate of generated bursts (default 1000)
  --speed M_PER_S     cmd-vel-envelope linear speed (default 3.0)
  --torque NM         lowcmd-torque joint torque, |NM| <= 127 (default 100)
  --attacker-ip IP    source address of attack frames (default 10.77.10.66)
  --lowcmd-target IP  the robot's low-level address (default 192.168.123.10)
";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("error: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

struct Args {
    cmd: String,
    scenarios: Vec<Scenario>,
    carrier: Option<PathBuf>,
    out: Option<PathBuf>,
    findings: Option<PathBuf>,
    target: Option<Ipv4Addr>,
    allow: Vec<Cidr>,
    i_understand: bool,
    json: bool,
    injected: Option<u64>,
    stagger: Duration,
    p: Params,
}

fn parse_scenarios(s: &str) -> Result<Vec<Scenario>, String> {
    if s == "all" {
        return Ok(Scenario::ALL.to_vec());
    }
    s.split(',')
        .map(|n| Scenario::parse(n).ok_or_else(|| format!("unknown scenario {n:?} (see `list`)")))
        .collect()
}

fn num<T: std::str::FromStr>(flag: &str, v: Option<String>) -> Result<T, String> {
    v.ok_or_else(|| format!("{flag} needs a value"))?
        .parse()
        .map_err(|_| format!("{flag}: not a valid value"))
}

fn parse(argv: Vec<String>) -> Result<Args, String> {
    let mut it = argv.into_iter();
    let cmd = it.next().ok_or("missing command")?;
    let mut a = Args {
        cmd,
        scenarios: Vec::new(),
        carrier: None,
        out: None,
        findings: None,
        target: None,
        allow: Vec::new(),
        i_understand: false,
        json: false,
        injected: None,
        stagger: Duration::from_secs(10),
        p: Params::default(),
    };
    while let Some(f) = it.next() {
        match f.as_str() {
            "--scenario" => {
                a.scenarios = parse_scenarios(&it.next().ok_or("--scenario needs a value")?)?
            }
            "--carrier" => a.carrier = Some(it.next().ok_or("--carrier needs a value")?.into()),
            "--out" => a.out = Some(it.next().ok_or("--out needs a value")?.into()),
            "--findings" => a.findings = Some(it.next().ok_or("--findings needs a value")?.into()),
            "--target" => a.target = Some(num("--target", it.next())?),
            "--allow" => a.allow.push(
                Cidr::parse(&it.next().ok_or("--allow needs a value")?)
                    .map_err(|e| e.to_string())?,
            ),
            "--i-understand" => a.i_understand = true,
            "--json" => a.json = true,
            "--injected-at-ms" => a.injected = Some(num(&f, it.next())?),
            "--seed" => a.p.seed = num(&f, it.next())?,
            "--at" => {
                a.p.at = Duration::from_secs_f64(num::<f64>(&f, it.next())?.clamp(0.0, 86_400.0))
            }
            "--stagger" => {
                a.stagger = Duration::from_secs_f64(num::<f64>(&f, it.next())?.clamp(0.0, 86_400.0))
            }
            "--count" => a.p.count = num(&f, it.next())?,
            "--rate" => a.p.rate_pps = num(&f, it.next())?,
            "--speed" => a.p.speed = num(&f, it.next())?,
            "--torque" => a.p.torque_nm = num(&f, it.next())?,
            "--attacker-ip" => a.p.attacker_ip = num(&f, it.next())?,
            "--lowcmd-target" => a.p.lowcmd_target = num(&f, it.next())?,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if !a.p.speed.is_finite() {
        return Err("--speed must be finite".into());
    }
    Ok(a)
}

fn list(as_json: bool) {
    if as_json {
        let v: Vec<_> = Scenario::ALL
            .iter()
            .map(|s| json!({"scenario": s.name(), "description": s.describe(), "expected_rule_ids": s.expected(), "needs_carrier": s.needs_carrier()}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    for s in Scenario::ALL {
        println!(
            "{}\n    {}\n    expects: {}",
            s.name(),
            s.describe(),
            s.expected().join(", ")
        );
    }
}

fn run(a: Args) -> Result<ExitCode, String> {
    match a.cmd.as_str() {
        "list" => {
            list(a.json);
            Ok(ExitCode::SUCCESS)
        }
        "pcap" => {
            if a.scenarios.is_empty() {
                return Err("--scenario is required".into());
            }
            let carrier_path = a.carrier.ok_or("--carrier is required")?;
            let out = a.out.ok_or("--out is required")?;
            let mut frames = read_capture(&carrier_path).map_err(|e| e.to_string())?;
            let base = frames.clone();
            let t0 = base.iter().map(|f| f.ts).min().unwrap_or_default();
            let mut timeline = Vec::new();
            // cmd-vel-envelope rewrites the carrier's own commands, so it
            // starts at --at whatever its place; the others are staggered.
            let mut slot = 0u32;
            for (i, s) in a.scenarios.iter().enumerate() {
                let mut p = a.p.clone();
                if *s != Scenario::CmdVelEnvelope {
                    p.at = a.p.at + a.stagger * slot;
                    slot = slot.saturating_add(1);
                }
                p.seed = a.p.seed.wrapping_add(i as u64);
                // Templates come from the original carrier, the frames go
                // into the accumulated output.
                let attack = attack_frames(*s, &base, &p).map_err(|e| format!("{s}: {e}"))?;
                frames = if *s == Scenario::CmdVelEnvelope {
                    generate(*s, &frames, &p).map_err(|e| format!("{s}: {e}"))?
                } else {
                    let mut f = frames;
                    f.extend(attack.iter().cloned());
                    f.sort_by_key(|x| x.ts);
                    f
                };
                timeline.push(json!({
                    "scenario": s.name(),
                    "start_offset_s": (t0 + p.at).saturating_sub(t0).as_secs_f64(),
                    "frames": attack.len(),
                    "expected_rule_ids": s.expected(),
                }));
            }
            write_capture(&out, &frames).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"out": out, "frames": frames.len(), "scenarios": timeline})
                )
                .unwrap_or_default()
            );
            Ok(ExitCode::SUCCESS)
        }
        "send" => {
            let [s] = a.scenarios.as_slice() else {
                return Err("send takes exactly one --scenario".into());
            };
            let target = a.target.ok_or("--target is required")?;
            let t = guard::check(target, &a.allow, a.i_understand).map_err(|e| e.to_string())?;
            let carrier = match &a.carrier {
                Some(p) => read_capture(p).map_err(|e| e.to_string())?,
                None => Vec::new(),
            };
            let frames = attack_frames(*s, &carrier, &a.p).map_err(|e| e.to_string())?;
            let r = guard::send(t, &frames).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({"scenario": s.name(), "target": target.to_string(), "sent": r.sent,
                       "skipped": r.skipped, "first_send_unix_ms": r.first_send_unix_ms,
                       "last_send_unix_ms": r.last_send_unix_ms, "expected_rule_ids": s.expected()})
            );
            Ok(ExitCode::SUCCESS)
        }
        "score" => {
            if a.scenarios.is_empty() {
                return Err("--scenario is required".into());
            }
            let path = a.findings.ok_or("--findings is required")?;
            let (seen, bad) = score::load(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut r = score::report(&a.scenarios, &seen, a.injected);
            r["unreadable"] = json!(bad);
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            Ok(if r["pass"] == true {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => return usage_err("arguments must be UTF-8"),
    };
    if argv.is_empty() || argv.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if argv.iter().any(|a| a == "-V" || a == "--version") {
        println!("robodr-attack-sim {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match parse(argv) {
        Ok(a) => match run(a) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Err(e) => usage_err(&e),
    }
}
