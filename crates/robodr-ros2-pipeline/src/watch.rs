//! `robodr-ros2-watch`: run the pipeline over a capture file or a live
//! interface and print findings as JSON lines. Lab tool, usable before the
//! Pulsar daemon is built. Argument parsing is std-only and lives here so it
//! is unit-tested; `src/bin/robodr-ros2-watch.rs` is a thin `main`.
//!
//! Output contract:
//! - **stdout**: one JSON object per finding, one per line, fields of
//!   [`ThreatExtra`](crate::ThreatExtra) (flushed per line, so it can be piped).
//! - **stderr**: human-readable status (profile warnings and errors, capture
//!   errors) and, with `--stats`, one final JSON object `{"pipeline": ..,
//!   "capture": ..}`.
//! - Exit code: `0` done, `1` runtime error (profile unreadable, capture
//!   cannot be opened, capture file truncated/corrupt), `2` usage error.
//!
//! Read-only: replay reads a file; live capture uses the same passive
//! `AF_PACKET` reader as the sensor (needs `CAP_NET_RAW`, never transmits).
//!
//! Hostile input: every capture byte goes through the pipeline, which never
//! panics and bounds both memory and output (per-datagram finding cap, rate
//! limits); all attacker text in a JSON line is sanitised. Argument values
//! are validated (ranges, unicast IPs, 24-hex prefixes) and echoed back
//! sanitised. Limit: in live mode held SEDP announcements (see
//! `crate::binding`) are reported on the next captured datagram, not on a
//! timer, because the capture source blocks; replays report them at the end.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

use crate::config::{capture_port_map, valid_ifname, CaptureInput, DEFAULT_READ_TIMEOUT_MS};
use crate::pipeline::{Pipeline, PipelineOptions, PipelineStats};
use crate::profile_trust::{load_profile_with_trust, ProfileTrustConfig};
use crate::sanitize::sanitize;
use crate::source::{CaptureDatagramSource, DatagramSource};

pub const USAGE: &str = "\
robodr-ros2-watch: run the RoboDR ROS 2 detection pipeline over captured RTPS
traffic and print each finding as one JSON line on stdout. Read-only.

USAGE:
    robodr-ros2-watch --profile <profile.json> --pcap <file>
    robodr-ros2-watch --profile <profile.json> --interface <name> [--interface <name>...]

INPUT (exactly one kind):
    --pcap <file>          replay a pcap or pcapng file
    --interface <name>     live capture on an interface (Linux, CAP_NET_RAW);
                           repeatable; 'any' = every interface

OPTIONS:
    --profile <file>       model profile (JSON). An invalid profile is reported
                           and the run is observe-only (never enforcing)
    --trusted-keys <file>  trusted profile signing keys (robodr-profile-trust/v1).
                           A locked profile is enforced only with a valid
                           <profile>.sig from one of them; without this
                           option every locked profile runs observe-only
    --profile-state <file> anti-rollback state (read, and rewritten when a
                           newer signed profile is accepted)
    --allow-rollback <sha256:HEX>
                           accept this exact (older) profile file once
    --expect-platform <p>  the profile's metadata.platform must be <p>
    --expect-unit <id>     the profile's metadata.unit_id must be null or <id>
    --trust-roots <file>   trust roots (robodr-trust-roots/v1): the trust
                           file must then be root-signed (floor, operators)
                           and the revocation list is verified
    --revocations <file>   signed profile revocation list
                           (robodr-profile-revocations/v2; needs --trust-roots)
    --revocations-required refuse every locked profile while the list file
                           is missing (default: optional until one was
                           accepted)
    --domain <id>          ROS_DOMAIN_ID whose well-known ports are captured
                           (repeatable, 0..=232; default 0). RTPS on other
                           ports is still caught by the 'RTPS' magic
    --dedup <n>            dedup capacity (default 4096)
    --no-anomalies         do not report RTPS parse anomalies
    --no-fragmentation     do not report fragmented discovery (rejected
                           fragments are always reported)
    --discovery-server <ip>
                           trust announcements relayed from this IP
                           (repeatable)
    --participant-ip <prefix>=<ip>
                           pin a GUID prefix (24 hex digits) to a source IP
                           (repeatable; several IPs per prefix allowed)
    --hold-ms <ms>         how long SEDP from a participant without SPDP is
                           held before it is reported (default 30000;
                           replays report what is still held at the end)
    --no-binding           disable the participant/source-IP binding check
    --duration <secs>      live only: stop after this many seconds (then
                           --stats is printed); default: run until killed
    --stats                print final counters as JSON on stderr
    -h, --help             this help
    -V, --version          version

EXIT: 0 done, 1 runtime error, 2 usage error.
";

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Help,
    Version,
    /// Boxed: [`WatchArgs`] is much larger than the other variants.
    Run(Box<WatchArgs>),
}

/// Parsed arguments of a run.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchArgs {
    pub profile: PathBuf,
    pub input: CaptureInput,
    pub domain_ids: Vec<u16>,
    pub options: PipelineOptions,
    pub stats: bool,
    pub read_timeout: Duration,
    /// Live only: stop after this long.
    pub duration: Option<Duration>,
    /// Profile trust (signature, anti-rollback); see
    /// [`crate::profile_trust`].
    pub trust: ProfileTrustConfig,
}

/// Parse `args` (without the program name).
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Command, String> {
    let mut profile = None;
    let mut pcap: Option<PathBuf> = None;
    let mut interfaces: Vec<String> = Vec::new();
    let mut any_interface = false;
    let mut domain_ids: Vec<u16> = Vec::new();
    let mut options = PipelineOptions::default();
    let mut stats = false;
    let mut duration = None;
    let mut trust = ProfileTrustConfig::default();
    let abs = |p: String| -> PathBuf {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            p
        } else {
            std::env::current_dir().map(|d| d.join(&p)).unwrap_or(p)
        }
    };
    let bad_ip = |flag: &str, v: &str| -> String {
        format!("{flag} {:?}: not a unicast IP address", sanitize(v))
    };
    let unicast = |ip: std::net::IpAddr| {
        !ip.is_unspecified()
            && !ip.is_multicast()
            && ip != std::net::IpAddr::from([255, 255, 255, 255])
    };

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        // A separate value must not look like a flag (`--profile --pcap x`
        // would otherwise take "--pcap" as the profile path); use the
        // `--flag=value` form for a value that really starts with "--".
        let mut value = |name: &str| -> Result<String, String> {
            let v = match inline.clone() {
                Some(v) => Some(v),
                None => it.next().filter(|v| !v.starts_with("--")),
            };
            match v {
                Some(v) if !v.is_empty() => Ok(v),
                _ => Err(format!("{name} needs a value")),
            }
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--profile" => {
                if profile
                    .replace(PathBuf::from(value("--profile")?))
                    .is_some()
                {
                    return Err("--profile given twice".into());
                }
            }
            "--trusted-keys" => {
                if trust
                    .trusted_keys
                    .replace(abs(value("--trusted-keys")?))
                    .is_some()
                {
                    return Err("--trusted-keys given twice".into());
                }
            }
            "--profile-state" => {
                if trust
                    .state_file
                    .replace(abs(value("--profile-state")?))
                    .is_some()
                {
                    return Err("--profile-state given twice".into());
                }
            }
            "--allow-rollback" => {
                if trust
                    .allow_rollback
                    .replace(value("--allow-rollback")?)
                    .is_some()
                {
                    return Err("--allow-rollback given twice".into());
                }
            }
            "--expect-platform" => {
                if trust
                    .expect_platform
                    .replace(value("--expect-platform")?)
                    .is_some()
                {
                    return Err("--expect-platform given twice".into());
                }
            }
            "--expect-unit" => {
                if trust
                    .expect_unit_id
                    .replace(value("--expect-unit")?)
                    .is_some()
                {
                    return Err("--expect-unit given twice".into());
                }
            }
            "--trust-roots" => {
                if trust
                    .trust_roots
                    .replace(abs(value("--trust-roots")?))
                    .is_some()
                {
                    return Err("--trust-roots given twice".into());
                }
            }
            "--revocations" => {
                if trust
                    .revocation_list
                    .replace(abs(value("--revocations")?))
                    .is_some()
                {
                    return Err("--revocations given twice".into());
                }
            }
            "--revocations-required" if inline.is_none() => {
                trust.revocation_policy = robodr_commission::trust::RevocationPolicy::Required;
            }
            "--pcap" => {
                if pcap.replace(PathBuf::from(value("--pcap")?)).is_some() {
                    return Err("--pcap given twice".into());
                }
            }
            "--interface" => {
                let name = value("--interface")?;
                if name == "any" {
                    any_interface = true;
                } else if !valid_ifname(&name) {
                    return Err(format!("invalid interface name {:?}", sanitize(&name)));
                } else if !interfaces.contains(&name) {
                    interfaces.push(name);
                }
            }
            "--domain" => {
                let v = value("--domain")?;
                let d: u16 = v
                    .parse()
                    .ok()
                    .filter(|d| u32::from(*d) <= crate::config::MAX_DOMAIN_ID)
                    .ok_or_else(|| {
                        format!("--domain {:?}: must be an integer 0..=232", sanitize(&v))
                    })?;
                if !domain_ids.contains(&d) {
                    domain_ids.push(d);
                }
            }
            "--dedup" => {
                let v = value("--dedup")?;
                options.dedup_capacity = v
                    .parse()
                    .ok()
                    .filter(|n| (1..=crate::dedup::MAX_DEDUP_CAPACITY).contains(n))
                    .ok_or_else(|| {
                        format!(
                            "--dedup {:?}: must be 1..={}",
                            sanitize(&v),
                            crate::dedup::MAX_DEDUP_CAPACITY
                        )
                    })?;
            }
            "--discovery-server" => {
                let v = value("--discovery-server")?;
                let ip = v
                    .parse()
                    .ok()
                    .filter(|ip| unicast(*ip))
                    .map(crate::binding::canonical_ip)
                    .ok_or_else(|| bad_ip("--discovery-server", &v))?;
                let servers = &mut options.binding.discovery_servers;
                if !servers.contains(&ip) {
                    if servers.len() >= crate::binding::MAX_DISCOVERY_SERVERS {
                        return Err("too many --discovery-server".into());
                    }
                    servers.push(ip);
                }
            }
            "--participant-ip" => {
                let v = value("--participant-ip")?;
                let (prefix, ip) = v
                    .split_once('=')
                    .ok_or_else(|| "--participant-ip needs <prefix>=<ip>".to_string())?;
                let prefix = crate::binding::parse_prefix(prefix).ok_or_else(|| {
                    format!(
                        "--participant-ip {:?}: prefix must be 24 hex digits",
                        sanitize(&v)
                    )
                })?;
                let ip = ip
                    .parse()
                    .ok()
                    .filter(|ip| unicast(*ip))
                    .map(crate::binding::canonical_ip)
                    .ok_or_else(|| bad_ip("--participant-ip", &v))?;
                let pins = &mut options.binding.participant_ips;
                if pins.len() >= crate::binding::MAX_PINNED_PARTICIPANTS
                    && !pins.contains_key(&prefix)
                {
                    return Err("too many --participant-ip prefixes".into());
                }
                let list = pins.entry(prefix).or_default();
                if !list.contains(&ip) {
                    if list.len() >= crate::binding::MAX_PINNED_IPS {
                        return Err("too many --participant-ip addresses for one prefix".into());
                    }
                    list.push(ip);
                }
            }
            "--hold-ms" => {
                let v = value("--hold-ms")?;
                let ms: u64 = v
                    .parse()
                    .ok()
                    .filter(|ms| *ms <= crate::config::MAX_HOLD_MS)
                    .ok_or_else(|| {
                        format!(
                            "--hold-ms {:?}: must be 0..={}",
                            sanitize(&v),
                            crate::config::MAX_HOLD_MS
                        )
                    })?;
                options.binding.hold = Duration::from_millis(ms);
            }
            "--no-binding" if inline.is_none() => options.binding.enabled = false,
            "--no-anomalies" if inline.is_none() => options.report_anomalies = false,
            "--no-fragmentation" if inline.is_none() => options.report_fragmentation = false,
            "--stats" if inline.is_none() => stats = true,
            "--duration" => {
                let v = value("--duration")?;
                let secs: u64 = v
                    .parse()
                    .ok()
                    .filter(|s| (1..=31_536_000).contains(s))
                    .ok_or_else(|| {
                        format!("--duration {:?}: seconds, 1..=31536000", sanitize(&v))
                    })?;
                duration = Some(Duration::from_secs(secs));
            }
            _ => return Err(format!("unknown argument {:?}", sanitize(&arg))),
        }
    }

    let profile = profile.ok_or("--profile is required")?;
    trust.validate().map_err(|e| sanitize(&e))?;
    let input = match (pcap, interfaces.is_empty() && !any_interface) {
        (Some(_), false) => return Err("--pcap and --interface are mutually exclusive".into()),
        (Some(path), true) => CaptureInput::Replay { path },
        (None, true) => return Err("one of --pcap or --interface is required".into()),
        (None, false) => {
            if any_interface && !interfaces.is_empty() {
                return Err("--interface any cannot be combined with named interfaces".into());
            }
            CaptureInput::Live { interfaces }
        }
    };
    if domain_ids.is_empty() {
        domain_ids.push(0);
    }
    if duration.is_some() && matches!(input, CaptureInput::Replay { .. }) {
        return Err("--duration only applies to live capture".into());
    }
    Ok(Command::Run(Box::new(WatchArgs {
        profile,
        input,
        domain_ids,
        options,
        stats,
        read_timeout: Duration::from_millis(DEFAULT_READ_TIMEOUT_MS),
        duration,
        trust,
    })))
}

/// Result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub findings: u64,
    pub stats: PipelineStats,
    /// The source ended with an error (e.g. truncated file) after
    /// delivering what it could.
    pub source_error: Option<String>,
}

#[derive(Serialize)]
struct FinalStats<'a> {
    pipeline: &'a PipelineStats,
}

/// Feed every datagram of `source` through `pipeline`, writing findings as
/// JSON lines to `out`: profile, binding and protocol findings per datagram,
/// capture-health findings as the source's counters grow, and at the end
/// ([`Pipeline::finish`]) the SEDP announcements still held for a
/// never-announced participant. Returns when the source ends.
pub fn run_source(
    pipeline: &mut Pipeline,
    source: &mut dyn DatagramSource,
    out: &mut dyn Write,
) -> io::Result<(u64, Option<String>)> {
    let mut n = 0u64;
    for f in pipeline.status_findings() {
        write_line(out, &f)?;
        n += 1;
    }
    loop {
        match source.recv() {
            Ok(Some(d)) => {
                let mut found = pipeline.process_datagram(&d);
                if let Some(h) = source.capture_health() {
                    found.extend(pipeline.capture_findings(&h));
                }
                for f in found {
                    write_line(out, &f)?;
                    n += 1;
                }
            }
            Ok(None) => return Ok((n + end_of_input(pipeline, source, out)?, None)),
            Err(e) => {
                let n = n + end_of_input(pipeline, source, out)?;
                return Ok((n, Some(sanitize(&e.to_string()))));
            }
        }
    }
}

/// Final capture-health and held-announcement findings.
fn end_of_input(
    pipeline: &mut Pipeline,
    source: &mut dyn DatagramSource,
    out: &mut dyn Write,
) -> io::Result<u64> {
    let mut found = Vec::new();
    if let Some(h) = source.capture_health() {
        found.extend(pipeline.capture_findings(&h));
    }
    found.extend(pipeline.finish());
    for f in &found {
        write_line(out, f)?;
    }
    Ok(found.len() as u64)
}

fn write_line(out: &mut dyn Write, f: &crate::Finding) -> io::Result<()> {
    let line = serde_json::to_string(&f.extra()).map_err(io::Error::other)?;
    writeln!(out, "{line}")?;
    out.flush()
}

/// Run a parsed command line. `Err` = runtime error (exit code 1).
pub fn run(args: &WatchArgs, out: &mut dyn Write, err: &mut dyn Write) -> Result<Summary, String> {
    for w in args.trust.warnings() {
        let _ = writeln!(err, "robodr-ros2-watch: warning: {}", sanitize(&w));
    }
    let loaded = load_profile_with_trust(&args.profile, &args.trust)?;
    let mut pipeline = Pipeline::from_loaded(loaded, args.options.clone());
    if let Some(msg) = pipeline.status_message() {
        let _ = writeln!(err, "robodr-ros2-watch: warning: {msg}");
    }
    let port_map = capture_port_map(&args.domain_ids);
    let mut source: Box<dyn DatagramSource> = match &args.input {
        CaptureInput::Replay { path } => Box::new(
            CaptureDatagramSource::open_file(path, port_map)
                .map_err(|e| sanitize(&e.to_string()))?,
        ),
        CaptureInput::Live { interfaces } => {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            if let Some(d) = args.duration {
                let flag = stop.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(d);
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                });
            }
            let settings = crate::config::CaptureSettings {
                input: CaptureInput::Live {
                    interfaces: interfaces.clone(),
                },
                domain_ids: args.domain_ids.clone(),
                port_map,
                read_timeout: args.read_timeout,
                queue_capacity: 1,
                legacy_udp_ports: Default::default(),
            };
            let src = settings.open(stop).map_err(|e| {
                format!(
                    "opening live capture on {}: {} (live capture needs CAP_NET_RAW)",
                    if interfaces.is_empty() {
                        "all interfaces".to_string()
                    } else {
                        interfaces.join(",")
                    },
                    sanitize(&e.to_string())
                )
            })?;
            let _ = writeln!(
                err,
                "robodr-ros2-watch: capturing live (read-only); Ctrl-C or --duration to stop"
            );
            src
        }
    };
    let (findings, source_error) =
        run_source(&mut pipeline, &mut source, out).map_err(|e| format!("writing output: {e}"))?;
    if let Some(e) = &source_error {
        let _ = writeln!(err, "robodr-ros2-watch: capture ended with an error: {e}");
    }
    if args.stats {
        let s = serde_json::to_string(&FinalStats {
            pipeline: pipeline.stats(),
        })
        .unwrap_or_default();
        let _ = writeln!(err, "{s}");
    }
    Ok(Summary {
        findings,
        stats: *pipeline.stats(),
        source_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    fn run_args(args: &[&str]) -> WatchArgs {
        match p(args).unwrap() {
            Command::Run(a) => *a,
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn revocation_and_trust_root_flags() {
        let a = run_args(&[
            "--profile",
            "p.json",
            "--pcap",
            "x.pcap",
            "--trust-roots",
            "/etc/robodr/trust-roots.json",
            "--revocations=/etc/robodr/profile-revocations.json",
            "--revocations-required",
        ]);
        assert_eq!(
            a.trust.trust_roots.as_deref(),
            Some(std::path::Path::new("/etc/robodr/trust-roots.json"))
        );
        assert_eq!(
            a.trust.revocation_list.as_deref(),
            Some(std::path::Path::new("/etc/robodr/profile-revocations.json"))
        );
        assert_eq!(
            a.trust.revocation_policy,
            robodr_commission::trust::RevocationPolicy::Required
        );
        // Relative paths are made absolute (the trust config requires it).
        let a = run_args(&[
            "--profile",
            "p.json",
            "--pcap",
            "x.pcap",
            "--trust-roots",
            "roots.json",
            "--revocations",
            "rev.json",
        ]);
        assert!(a.trust.trust_roots.unwrap().is_absolute());
        assert_eq!(
            a.trust.revocation_policy,
            robodr_commission::trust::RevocationPolicy::Optional
        );
        // A list needs roots; required needs a list; no duplicates.
        assert!(
            p(&["--profile", "p", "--pcap", "x", "--revocations", "/r.json"])
                .unwrap_err()
                .contains("trust_roots")
        );
        assert!(p(&["--profile", "p", "--pcap", "x", "--revocations-required"]).is_err());
        assert!(p(&[
            "--profile",
            "p",
            "--pcap",
            "x",
            "--trust-roots",
            "/a",
            "--trust-roots",
            "/b"
        ])
        .unwrap_err()
        .contains("twice"));
        assert!(USAGE.contains("--revocations-required"));
    }

    #[test]
    fn help_and_version() {
        assert_eq!(p(&["--help"]).unwrap(), Command::Help);
        assert_eq!(p(&["-h", "--bogus"]).unwrap(), Command::Help);
        assert_eq!(p(&["-V"]).unwrap(), Command::Version);
    }

    #[test]
    fn pcap_run_with_defaults() {
        let a = run_args(&["--profile", "/p.json", "--pcap", "x.pcap"]);
        assert_eq!(a.profile, PathBuf::from("/p.json"));
        assert_eq!(
            a.input,
            CaptureInput::Replay {
                path: "x.pcap".into()
            }
        );
        assert_eq!(a.domain_ids, vec![0]);
        assert_eq!(a.options, PipelineOptions::default());
        assert!(!a.stats);
    }

    #[test]
    fn live_run_with_options_and_equals_form() {
        let a = run_args(&[
            "--profile=/p.json",
            "--interface",
            "lo",
            "--interface=eth0",
            "--interface",
            "lo",
            "--domain",
            "3",
            "--domain=3",
            "--domain",
            "232",
            "--dedup",
            "10",
            "--no-anomalies",
            "--no-fragmentation",
            "--stats",
        ]);
        assert_eq!(
            a.input,
            CaptureInput::Live {
                interfaces: vec!["lo".into(), "eth0".into()]
            }
        );
        assert_eq!(a.domain_ids, vec![3, 232]);
        assert_eq!(a.options.dedup_capacity, 10);
        assert!(!a.options.report_anomalies && !a.options.report_fragmentation);
        assert!(a.stats);
        let a = run_args(&[
            "--profile",
            "/p",
            "--pcap",
            "x",
            "--discovery-server",
            "10.0.0.2",
            "--discovery-server=::ffff:10.0.0.2",
            "--participant-ip",
            "AAAAAAAAAAAAAAAAAAAAAAAA=10.0.0.5",
            "--participant-ip=aaaaaaaaaaaaaaaaaaaaaaaa=10.0.0.6",
            "--hold-ms",
            "0",
            "--no-binding",
        ]);
        let b = &a.options.binding;
        assert_eq!(
            b.discovery_servers,
            vec![std::net::IpAddr::from([10, 0, 0, 2])]
        );
        assert_eq!(b.participant_ips[&[0xaa; 12]].len(), 2);
        assert_eq!(b.hold, Duration::ZERO);
        assert!(!b.enabled);
        let a = run_args(&["--profile", "/p", "--interface", "any", "--duration", "5"]);
        assert_eq!(a.input, CaptureInput::Live { interfaces: vec![] });
        assert_eq!(a.duration, Some(Duration::from_secs(5)));
        assert!(p(&["--profile", "/p", "--pcap", "x", "--duration", "5"]).is_err());
        assert!(p(&["--profile", "/p", "--interface", "lo", "--duration", "0"]).is_err());
    }

    #[test]
    fn usage_errors() {
        for bad in [
            &[][..],
            &["--pcap", "x"],
            &["--profile", "/p"],
            &["--profile", "/p", "--pcap", "x", "--interface", "lo"],
            &["--profile", "/p", "--pcap"],
            &["--profile", "/p", "--pcap="],
            &["--profile", "/p", "--profile", "/q", "--pcap", "x"],
            &["--profile", "/p", "--pcap", "x", "--pcap", "y"],
            &["--profile", "/p", "--pcap", "x", "--domain", "233"],
            &["--profile", "/p", "--pcap", "x", "--domain", "-1"],
            &["--profile", "/p", "--pcap", "x", "--dedup", "0"],
            &["--profile", "/p", "--interface", "a/b"],
            &["--profile", "/p", "--interface", "any", "--interface", "lo"],
            &["--profile", "/p", "--pcap", "x", "--stats=yes"],
            &["--profile", "/p", "--pcap", "x", "extra"],
            &["--profile", "/p", "--pcap", "x", "--evil\n\u{1b}"],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--discovery-server",
                "0.0.0.0",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--discovery-server",
                "nope\n",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--discovery-server",
                "aaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--discovery-server",
                "aaaaaaaaaaaaaaaaaaaaaaaa@10.0.0.2",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--participant-ip",
                "aa=10.0.0.1",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--participant-ip",
                "10.0.0.1",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--participant-ip",
                "aaaaaaaaaaaaaaaaaaaaaaaa=239.1.1.1",
            ],
            &["--profile", "/p", "--pcap", "x", "--hold-ms", "600001"],
            &["--profile", "/p", "--pcap", "x", "--no-binding=1"],
            &["--profile", "--pcap", "x"],
            &["--profile", "/p", "--pcap", "x", "--hold-ms", "--stats"],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--participant-ip",
                "=10.0.0.1",
            ],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--participant-ip",
                "aaaaaaaaaaaaaaaaaaaaaaaa=",
            ],
            &["--profile", "/p", "--pcap", "x", "--hold-ms", "-1"],
            &["--profile", "/p", "--pcap", "x", "--hold-ms", "1e3"],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--hold-ms",
                "18446744073709551616",
            ],
            &["--profile", "/p", "--pcap", "x", "--dedup", "NaN"],
            &["--profile", "/p", "--pcap", "x", "--dedup", "inf"],
            &["--profile", "/p", "--pcap", "x", "--domain", "\u{202e}0"],
            &[
                "--profile",
                "/p",
                "--pcap",
                "x",
                "--discovery-server",
                "255.255.255.255",
            ],
            &["--profile", "/p", "--pcap", "x", "--discovery-server", "::"],
        ] {
            let e = p(bad).unwrap_err();
            assert!(!e.chars().any(char::is_control), "{e:?}");
        }
    }

    #[test]
    fn run_reports_missing_profile_and_capture() {
        let a = run_args(&["--profile", "/nonexistent/p.json", "--pcap", "/x"]);
        let (mut o, mut e) = (Vec::new(), Vec::new());
        assert!(run(&a, &mut o, &mut e)
            .unwrap_err()
            .contains("reading profile"));
    }
}
