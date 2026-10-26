//! Loading (configuration, profile with its trust checks, firewall
//! configuration) and the NFQUEUE run loop, shared by the binary and the
//! end-to-end test.
//!
//! The loop is single-threaded: `recv` a batch from the queue, and for each
//! packet copy it, [`Gateway::process`] it, send the verdict. Everything
//! that allocates or does I/O (draining firewall events to the events file,
//! the status file, the writer-map state file, identity lease expiry,
//! `WATCHDOG=1`) runs in **housekeeping**, after the verdicts of the batch
//! were sent and at most every `housekeeping_ms`. The receive timeout is
//! the housekeeping period, so an idle queue still runs it (the systemd
//! watchdog therefore sees a stalled loop, not an idle one).
//!
//! The loop measures, per packet, the time from the moment its batch was
//! received to the moment its verdict was sent (`recv -> verdict`), and
//! reports p50 / p99 / max in the status file.

use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use robodr_events::profile::Profile;
use robodr_firewall::FirewallConfig;
use serde_json::json;

use crate::config::{GatewayConfig, GatewayMode, OnGatewayDown};
use crate::gateway::{Gateway, PacketMeta, Verdict};
use crate::nfq::{self, Item};
use crate::sys;

/// Read a small text file (size-capped).
fn read_capped(path: &Path, max: u64) -> Result<String, String> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut s = String::new();
    f.take(max + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if s.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", path.display()));
    }
    Ok(s)
}

/// Load the profile (commissioning + trust checks, the anti-rollback state
/// is read, never written) and the firewall configuration. In enforce mode
/// a profile that fails its checks is an error: the gateway cannot vouch
/// for any decision, so it does not start and the queue's
/// `on_gateway_down` behaviour applies. In observe mode it is used
/// unlocked (observe only).
pub fn load(cfg: &GatewayConfig) -> Result<(Profile, FirewallConfig, Vec<String>), String> {
    let mut notes = Vec::new();
    let (loaded, _commit) = robodr_ros2_pipeline::profile_trust::load_profile_deferred(
        &cfg.profile,
        &cfg.profile_trust,
    )?;
    let mut profile = loaded.profile;
    if let Err(e) = &loaded.file_check {
        if cfg.mode == GatewayMode::Enforce {
            return Err(format!(
                "profile {} cannot be enforced: {e:?}",
                cfg.profile.display()
            ));
        }
        notes.push(format!(
            "profile check failed ({e:?}): observing with an unlocked profile"
        ));
        profile.locked = false;
    }
    let text = read_capped(&cfg.firewall, crate::config::MAX_CONFIG_BYTES)?;
    let fw = FirewallConfig::from_json(&text)
        .map_err(|e| format!("{}: {e:?}", cfg.firewall.display()))?;
    Ok((profile, fw, notes))
}

/// Recv -> verdict latency histogram (1 µs buckets up to 20 ms, then one
/// overflow bucket).
#[derive(Debug, Clone)]
pub struct LatencyHist {
    buckets: Vec<u64>,
    pub count: u64,
    pub max_ns: u64,
}

const BUCKET_NS: u64 = 1_000;
const BUCKETS: usize = 20_000;

impl Default for LatencyHist {
    fn default() -> Self {
        Self {
            buckets: vec![0; BUCKETS + 1],
            count: 0,
            max_ns: 0,
        }
    }
}

impl LatencyHist {
    pub fn record(&mut self, ns: u64) {
        let i = usize::try_from(ns / BUCKET_NS)
            .unwrap_or(BUCKETS)
            .min(BUCKETS);
        if let Some(b) = self.buckets.get_mut(i) {
            *b += 1;
        }
        self.count += 1;
        self.max_ns = self.max_ns.max(ns);
    }

    /// Upper bound of the bucket holding quantile `q` (ns).
    pub fn quantile_ns(&self, q: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let want = ((self.count as f64) * q).ceil().max(1.0) as u64;
        let mut acc = 0;
        for (i, b) in self.buckets.iter().enumerate() {
            acc += b;
            if acc >= want {
                return ((i as u64) + 1) * BUCKET_NS;
            }
        }
        self.max_ns
    }
}

/// Run-loop options beyond the configuration.
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    /// Stop after this many packets (tests); `None` = until a signal.
    pub max_packets: Option<u64>,
    /// Stop after this long (tests).
    pub max_duration: Option<Duration>,
}

/// What a finished run reports.
#[derive(Debug, Clone)]
pub struct RunReport {
    pub packets: u64,
    /// Packets that carried a kernel receive timestamp.
    pub stamped: u64,
    pub latency: LatencyHist,
}

/// Open the queue and run until a shutdown signal (or the options' limits).
pub fn run(
    cfg: &GatewayConfig,
    gw: &mut Gateway,
    opts: RunOptions,
    stop: &dyn Fn() -> bool,
) -> Result<RunReport, String> {
    let fail_open = cfg.queue.on_gateway_down == OnGatewayDown::Bypass;
    let mut q = nfq::Queue::open(cfg.queue.num, cfg.queue.max_len, fail_open).map_err(|e| {
        format!(
            "NFQUEUE {}: {e} (needs CAP_NET_ADMIN and nfnetlink_queue)",
            cfg.queue.num
        )
    })?;
    let hk = Duration::from_millis(cfg.housekeeping_ms);
    q.set_timeout(hk).map_err(|e| format!("SO_RCVTIMEO: {e}"))?;
    if let Some(p) = &cfg.rtps.state_file {
        match gw.discovery_mut().load(p) {
            Ok(n) if n > 0 => eprintln!(
                "robodr-firewall-gw: {n} enforced writers restored from {}",
                p.display()
            ),
            Ok(_) => {}
            Err(e) => eprintln!("robodr-firewall-gw: ignoring writer state: {e}"),
        }
    }
    let notifier = sys::Notifier::from_env();
    notifier.notify("READY=1\nSTATUS=deciding");
    let mut events = Events::open(cfg);
    let mut hist = LatencyHist::default();
    let mut work: Vec<u8> = Vec::with_capacity(65_536);
    let started = Instant::now();
    let mut next_hk = Instant::now() + hk;
    let mut packets = 0u64;
    let mut stamped = 0u64;
    let mut last_now = 0u64;
    let observe = gw.mode() == GatewayMode::Observe;
    let mut send_err: Option<String> = None;
    while !stop() && !sys::shutdown_requested() {
        if opts.max_packets.is_some_and(|m| packets >= m)
            || opts.max_duration.is_some_and(|d| started.elapsed() >= d)
        {
            break;
        }
        let n = q.recv().map_err(|e| format!("NFQUEUE recv: {e}"))?;
        if n > 0 {
            let t_batch = sys::monotonic_ns();
            let buf = std::mem::take(&mut q.buf);
            nfq::parse_packets(&buf[..n], |item| {
                let Item::Packet(p) = item else { return };
                packets += 1;
                let (verdict, payload) = if p.cap_len.is_some() || p.hw_protocol != 0x0800 {
                    // Truncated copy or not IPv4: nothing the gateway can
                    // decide on.
                    (
                        if observe {
                            nfq::NF_ACCEPT
                        } else {
                            nfq::NF_DROP
                        },
                        None,
                    )
                } else {
                    work.clear();
                    work.extend_from_slice(p.payload);
                    // The firewall's clock is the packet's ARRIVAL time when
                    // the kernel stamped it (mapped into CLOCK_MONOTONIC):
                    // a backlog the gateway drains after a scheduling stall
                    // must keep the sender's spacing, or its frames would be
                    // refused as "too early". Never decreasing.
                    let mono = sys::monotonic_ns();
                    let real = sys::realtime_ns();
                    let delay = p.timestamp.and_then(|(s, us)| {
                        let t = s
                            .checked_mul(1_000_000_000)?
                            .checked_add(us.checked_mul(1_000)?)?;
                        real.checked_sub(t)
                    });
                    if delay.is_some() {
                        stamped += 1;
                    }
                    let arrival = delay.map_or(mono, |d| mono.saturating_sub(d));
                    let now = arrival.max(last_now);
                    last_now = now;
                    let meta = PacketMeta {
                        now_ns: now,
                        queue_delay_ns: delay,
                        instant: Instant::now(),
                    };
                    match gw.process(&mut work, meta) {
                        Verdict::Accept => (nfq::NF_ACCEPT, None),
                        Verdict::AcceptModified => (nfq::NF_ACCEPT, Some(work.as_slice())),
                        Verdict::Drop => (nfq::NF_DROP, None),
                    }
                };
                if let Err(e) = q.verdict(p.id, verdict, payload) {
                    send_err.get_or_insert(e.to_string());
                }
                hist.record(sys::monotonic_ns().saturating_sub(t_batch));
            });
            q.buf = buf;
            if let Some(e) = send_err.take() {
                return Err(format!("NFQUEUE verdict: {e}"));
            }
        }
        if Instant::now() >= next_hk {
            next_hk = Instant::now() + hk;
            housekeeping(cfg, gw, &mut events, &hist);
            notifier.notify("WATCHDOG=1");
        }
    }
    housekeeping(cfg, gw, &mut events, &hist);
    notifier.notify("STOPPING=1");
    Ok(RunReport {
        packets,
        stamped,
        latency: hist,
    })
}

/// The events file (JSON lines of firewall deviations), size-capped.
struct Events {
    file: Option<std::io::BufWriter<std::fs::File>>,
    written: u64,
    max: u64,
    dropped: u64,
}

impl Events {
    fn open(cfg: &GatewayConfig) -> Self {
        let file = cfg.events_path.as_ref().and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| eprintln!("robodr-firewall-gw: events file {}: {e}", p.display()))
                .ok()
                .map(std::io::BufWriter::new)
        });
        let written = cfg
            .events_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |m| m.len());
        Self {
            file,
            written,
            max: cfg.events_max_bytes,
            dropped: 0,
        }
    }
}

fn housekeeping(cfg: &GatewayConfig, gw: &mut Gateway, events: &mut Events, hist: &LatencyHist) {
    let devs = gw.firewall_mut().drain_deviations();
    for d in devs {
        let Some(f) = events.file.as_mut() else {
            continue;
        };
        let Ok(line) = serde_json::to_string(&d) else {
            continue;
        };
        if events.written + line.len() as u64 + 1 > events.max {
            events.dropped += 1;
            continue;
        }
        if writeln!(f, "{line}").is_ok() {
            events.written += line.len() as u64 + 1;
        }
    }
    if let Some(f) = events.file.as_mut() {
        let _ = f.flush();
    }
    gw.discovery_mut().expire(Instant::now());
    if let Some(p) = &cfg.rtps.state_file {
        if gw.discovery().dirty {
            if let Err(e) = gw.discovery_mut().save(p) {
                eprintln!("robodr-firewall-gw: writer state {}: {e}", p.display());
            }
        }
    }
    if let Some(p) = &cfg.status_path {
        let fs = gw.firewall().stats();
        let status = json!({
            "format": "robodr-firewall-gw-status/v1",
            "mode": match gw.mode() { GatewayMode::Enforce => "enforce", GatewayMode::Observe => "observe" },
            "updated_mono_ms": sys::monotonic_ns() / 1_000_000,
            "stale_after_ms": cfg.housekeeping_ms * 10,
            "gateway": gw.stats,
            "discovery": gw.discovery().stats,
            "writers_known": gw.discovery().len(),
            "firewall": {
                "checked": fs.checked, "passed": fs.passed, "limited": fs.limited,
                "rejected": fs.rejected, "would_have": fs.would_have, "faults": fs.faults,
                "joint_hold_episodes": fs.joint_hold_episodes,
                "joint_holds_exceeded": fs.joint_holds_exceeded,
                "joint_hold_age_ns": fs.joint_hold_age_ns,
            },
            "latency_recv_to_verdict_ns": {
                "count": hist.count,
                "p50": hist.quantile_ns(0.50),
                "p99": hist.quantile_ns(0.99),
                "max": hist.max_ns,
            },
            "events_dropped_size_cap": events.dropped,
        });
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, status.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}
