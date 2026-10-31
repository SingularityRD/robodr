//! `robodr-bench`: run the throughput suite, one child process per workload.
//!
//! ```text
//! robodr-bench [--quick] [--out results.json] [--gate baseline.json] [--tolerance 0.3]
//! robodr-bench run-one agentd P T HZ SECS ROGUE_SHARE | correlate SIGNALS GROUPS
//! ```
//!
//! Exit 0 on success; 1 when `--gate` finds a regression; 2 on errors.

#![forbid(unsafe_code)]

use robodr_benches::{gate, run_agentd, run_correlate, suite, AgentdLoad, CorrelateLoad};
use serde_json::{json, Value};
use std::process::{Command, ExitCode};

fn arg<T: std::str::FromStr>(v: Option<&String>) -> Result<T, String> {
    v.ok_or("missing argument")?
        .parse()
        .map_err(|_| "bad number".to_string())
}

fn run_one(args: &[String]) -> Result<Value, String> {
    match args.first().map(String::as_str) {
        Some("agentd") => run_agentd(&AgentdLoad {
            participants: arg(args.get(1))?,
            topics: arg(args.get(2))?,
            motion_hz: arg(args.get(3))?,
            seconds: arg(args.get(4))?,
            rogue_share: arg(args.get(5))?,
        }),
        Some("correlate") => run_correlate(&CorrelateLoad {
            signals: arg(args.get(1))?,
            groups: arg(args.get(2))?,
        }),
        _ => Err("run-one agentd|correlate ...".into()),
    }
}

fn child(args: Vec<String>) -> Result<Value, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let o = Command::new(exe)
        .arg("run-one")
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("{args:?}: {}", String::from_utf8_lossy(&o.stderr)));
    }
    serde_json::from_slice(&o.stdout).map_err(|e| e.to_string())
}

fn host() -> Value {
    let cpu = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("model name"))
            .map(|v| v.trim_start_matches([' ', '\t', ':']).to_string())
    });
    json!({
        "cpu": cpu,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "arch": std::env::consts::ARCH,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("run-one") {
        return match run_one(&argv[1..]) {
            Ok(v) => {
                println!("{v}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    let mut quick = false;
    let mut out = None;
    let mut baseline = None;
    let mut tolerance = 0.3f64;
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--quick" => quick = true,
            "--out" => out = it.next().cloned(),
            "--gate" => baseline = it.next().cloned(),
            "--tolerance" => {
                tolerance = it.next().and_then(|v| v.parse().ok()).unwrap_or(tolerance)
            }
            "--bench" => {} // passed by `cargo bench`
            other => {
                eprintln!("error: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let (agentd, correlate) = suite(quick);
    let mut results = Vec::new();
    for l in &agentd {
        let args = vec![
            "agentd".to_string(),
            l.participants.to_string(),
            l.topics.to_string(),
            l.motion_hz.to_string(),
            l.seconds.to_string(),
            l.rogue_share.to_string(),
        ];
        match child(args) {
            Ok(v) => {
                eprintln!(
                    "{}: {:.0} datagrams/s, {:.1}x real time, peak RSS {} KiB",
                    l.name(),
                    v["datagrams_per_s"].as_f64().unwrap_or(0.0),
                    v["realtime_factor"].as_f64().unwrap_or(0.0),
                    v["peak_rss_kib"]
                );
                results.push(v);
            }
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }
    for l in &correlate {
        match child(vec![
            "correlate".into(),
            l.signals.to_string(),
            l.groups.to_string(),
        ]) {
            Ok(v) => {
                eprintln!(
                    "{}: {:.0} signals/s, peak RSS {} KiB",
                    l.name(),
                    v["signals_per_s"].as_f64().unwrap_or(0.0),
                    v["peak_rss_kib"]
                );
                results.push(v);
            }
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let report = json!({"host": host(), "quick": quick, "results": results});
    let text = serde_json::to_string_pretty(&report).unwrap_or_default();
    match &out {
        Some(p) => {
            if let Err(e) = std::fs::write(p, format!("{text}\n")) {
                eprintln!("error: {p}: {e}");
                return ExitCode::from(2);
            }
        }
        None => println!("{text}"),
    }
    if let Some(b) = baseline {
        let base: Value = match std::fs::read(&b)
            .map_err(|e| e.to_string())
            .and_then(|x| serde_json::from_slice(&x).map_err(|e| e.to_string()))
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {b}: {e}");
                return ExitCode::from(2);
            }
        };
        let empty = Vec::new();
        let problems = gate(
            &results,
            base["results"].as_array().unwrap_or(&empty),
            tolerance,
        );
        if !problems.is_empty() {
            for p in &problems {
                eprintln!("REGRESSION {p}");
            }
            return ExitCode::from(1);
        }
        eprintln!("gate: no regression against {b} (tolerance {tolerance})");
    }
    ExitCode::SUCCESS
}
