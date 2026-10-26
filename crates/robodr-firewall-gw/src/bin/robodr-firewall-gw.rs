//! `robodr-firewall-gw`: the in-path Motion Firewall gateway (see the crate
//! README).
//!
//! ```text
//! robodr-firewall-gw run          --config /etc/robodr/firewall-gw.json
//! robodr-firewall-gw check-config --config /etc/robodr/firewall-gw.json
//! robodr-firewall-gw ruleset      --config /etc/robodr/firewall-gw.json
//! ```
//!
//! Exit codes: 0 ok, 1 runtime failure, 2 usage / configuration error.

use std::path::PathBuf;
use std::process::ExitCode;

use robodr_firewall_gw::config::GatewayConfig;
use robodr_firewall_gw::runtime::{self, RunOptions};
use robodr_firewall_gw::{ruleset, sys, Gateway};

const USAGE: &str = "usage: robodr-firewall-gw <run|check-config|ruleset> --config <path>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if matches!(cmd, "-h" | "--help" | "help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let config = match rest {
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let cfg = match GatewayConfig::load(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("robodr-firewall-gw: {e}");
            return ExitCode::from(2);
        }
    };
    match cmd {
        "ruleset" => {
            print!("{}", ruleset::render(&cfg, &config.display().to_string()));
            ExitCode::SUCCESS
        }
        "check-config" | "run" => {
            let (profile, fw, notes) = match runtime::load(&cfg) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("robodr-firewall-gw: {e}");
                    return ExitCode::from(2);
                }
            };
            for n in notes {
                eprintln!("robodr-firewall-gw: warning: {n}");
            }
            let mut gw = match Gateway::new(&cfg, &profile, &fw) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("robodr-firewall-gw: {e}");
                    return ExitCode::from(2);
                }
            };
            if cmd == "check-config" {
                println!(
                    "robodr-firewall-gw: configuration ok ({} channel(s), mode {:?}, queue {}, on_gateway_down {:?})",
                    cfg.channels.len(),
                    cfg.mode,
                    cfg.queue.num,
                    cfg.queue.on_gateway_down
                );
                return ExitCode::SUCCESS;
            }
            if let Err(e) = sys::install_signals() {
                eprintln!("robodr-firewall-gw: signals: {e}");
                return ExitCode::from(1);
            }
            let opts = RunOptions {
                max_packets: None,
                max_duration: None,
            };
            match runtime::run(&cfg, &mut gw, opts, &|| false) {
                Ok(r) => {
                    eprintln!(
                        "robodr-firewall-gw: stopped after {} packets (recv->verdict p50 {} ns, p99 {} ns, max {} ns)",
                        r.packets,
                        r.latency.quantile_ns(0.5),
                        r.latency.quantile_ns(0.99),
                        r.latency.max_ns
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("robodr-firewall-gw: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
