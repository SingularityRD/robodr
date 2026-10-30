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
//! **Robot-side copies** (`observe.enabled`): an NFLOG group receives a
//! copy of every UDP datagram entering from the robot port
//! (`crate::observe`). The group is drained without blocking before each
//! NFQUEUE receive and again right before a received batch is decided, so
//! the robot's latest `rt/lowstate` is known when an arm-SDK frame is. The
//! copies are never verdicted; a full socket buffer loses copies only
//! (`observe_overruns`). If the group cannot be bound the gateway runs
//! without observation (a WARNING, status `observe_unavailable`): the
//! arm-SDK engagement then uses its conservative first-step rule.
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
use crate::{nflog, sys};

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
    eprintln!(
        "robodr-firewall-gw: queued RTPS port ranges {:?}; discovery announcing a locator \
         outside them raises port_bypass_risk",
        cfg.rtps_port_ranges()
    );
    let mut log = if cfg.observe.enabled {
        match nflog::Log::open(cfg.observe.nflog_group) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!(
                    "robodr-firewall-gw: WARNING: NFLOG group {} ({e}; needs nfnetlink_log): \
                     running without robot-side observation (no rt/lowstate for the arm-SDK \
                     engagement check, no robot-side locator check); status observe_unavailable",
                    cfg.observe.nflog_group
                );
                None
            }
        }
    } else {
        None
    };
    let observe_unavailable = cfg.observe.enabled && log.is_none();
    // Controller-side WebRTC copies (`crate::webrtc`), a group of their own
    // so they never reach the robot-side discovery observer.
    let mut rtc_log = match &cfg.webrtc {
        Some(w) => match nflog::Log::open(w.nflog_group) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!(
                    "robodr-firewall-gw: WARNING: NFLOG group {} ({e}): the WebRTC monitor sees \
                     only the robot side of sessions",
                    w.nflog_group
                );
                None
            }
        },
        None => None,
    };
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
        drain_observed(&mut log, gw, true);
        drain_observed(&mut rtc_log, gw, false);
        let n = q.recv().map_err(|e| format!("NFQUEUE recv: {e}"))?;
        if n > 0 {
            drain_observed(&mut log, gw, true);
            drain_observed(&mut rtc_log, gw, false);
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
                        src_mac: p.hwaddr,
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
            events.observe_unavailable = observe_unavailable;
            events.observe_overruns = log.as_ref().map_or(0, |l| l.overruns);
            housekeeping(cfg, gw, &mut events, &hist);
            notifier.notify("WATCHDOG=1");
        }
    }
    events.observe_unavailable = observe_unavailable;
    events.observe_overruns = log.as_ref().map_or(0, |l| l.overruns);
    housekeeping(cfg, gw, &mut events, &hist);
    notifier.notify("STOPPING=1");
    Ok(RunReport {
        packets,
        stamped,
        latency: hist,
    })
}

/// Most NFLOG receives per drain (bounds the time taken from the queue).
const MAX_OBSERVE_RECVS: usize = 64;

/// Hand the pending robot-side copies to the gateway (never blocks).
/// `robot_side`: the observe group (robot-side copies, also fed to the
/// discovery / `rt/lowstate` observer); otherwise the WebRTC group.
fn drain_observed(log: &mut Option<nflog::Log>, gw: &mut Gateway, robot_side: bool) {
    let Some(l) = log.as_mut() else {
        return;
    };
    for _ in 0..MAX_OBSERVE_RECVS {
        let n = match l.try_recv() {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let buf = std::mem::take(&mut l.buf);
        let mono = sys::monotonic_ns();
        let real = sys::realtime_ns();
        nflog::parse_packets(&buf[..n], |item| {
            let nflog::Item::Packet(p) = item else { return };
            if p.hw_protocol != 0x0800 {
                return;
            }
            // Its arrival on the box, on the decision clock (as for queued
            // packets).
            let delay = p.timestamp.and_then(|(s, us)| {
                let t = s
                    .checked_mul(1_000_000_000)?
                    .checked_add(us.checked_mul(1_000)?)?;
                real.checked_sub(t)
            });
            let meta = PacketMeta {
                now_ns: delay.map_or(mono, |d| mono.saturating_sub(d)),
                queue_delay_ns: None,
                instant: Instant::now(),
                src_mac: None,
            };
            let wall = p
                .timestamp
                .and_then(|(s, us)| {
                    s.checked_mul(1_000_000_000)?
                        .checked_add(us.checked_mul(1_000)?)
                })
                .unwrap_or(real);
            gw.observe_webrtc(p.payload, meta.now_ns, wall);
            if robot_side {
                gw.observe(p.payload, meta);
            }
        });
        l.buf = buf;
    }
}

/// The events file (JSON lines of firewall deviations), size-capped.
struct Events {
    file: Option<std::io::BufWriter<std::fs::File>>,
    written: u64,
    max: u64,
    dropped: u64,
    /// The port-bypass warning was printed.
    port_warned: bool,
    /// Status: the NFLOG group could not be bound / copies lost.
    observe_unavailable: bool,
    observe_overruns: u64,
    /// agentd's gateway feed (`findings_socket`), on its own thread.
    feed: Option<crate::feed::FeedThread>,
    /// The restriction file, read on its own thread.
    watcher: Option<crate::restrict::Watcher>,
    /// The last restriction file error (status `restriction_error`).
    restriction_error: Option<String>,
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
            port_warned: false,
            observe_unavailable: false,
            observe_overruns: 0,
            feed: cfg.findings_socket.clone().and_then(|p| {
                crate::feed::FeedThread::spawn(p)
                    .map_err(|e| eprintln!("robodr-firewall-gw: findings feed thread: {e}"))
                    .ok()
            }),
            watcher: cfg.restriction_path.clone().and_then(|p| {
                crate::restrict::Watcher::spawn(p, Duration::from_millis(cfg.housekeeping_ms))
                    .map_err(|e| eprintln!("robodr-firewall-gw: restriction thread: {e}"))
                    .ok()
            }),
            restriction_error: None,
        }
    }
}

/// Apply the restriction watcher's latest read (`latest`, `None`: nothing
/// new) to the gateway; an expired restriction is lifted whatever was
/// read (the gateway enforces the TTL itself). Returns the read error to
/// report, or the previous one when nothing new arrived.
pub fn apply_restriction(
    gw: &mut Gateway,
    latest: Option<Result<Option<crate::restrict::Restriction>, String>>,
    previous_error: Option<String>,
    now_unix_ms: u64,
) -> Option<String> {
    let err = match latest {
        None => previous_error,
        Some(Ok(Some(r))) if !r.expired(now_unix_ms) => {
            gw.set_restriction(Some(r));
            None
        }
        Some(Ok(_)) => {
            gw.set_restriction(None);
            None
        }
        // Never "no restriction" silently: the one in force stays until
        // its own expiry, and the status says why.
        Some(Err(e)) => Some(e),
    };
    if gw.restriction().is_some_and(|r| r.expired(now_unix_ms)) {
        gw.set_restriction(None);
    }
    err
}

fn housekeeping(cfg: &GatewayConfig, gw: &mut Gateway, events: &mut Events, hist: &LatencyHist) {
    let latest = events.watcher.as_ref().and_then(|w| w.latest());
    let err = apply_restriction(
        gw,
        latest,
        events.restriction_error.clone(),
        sys::realtime_ns() / 1_000_000,
    );
    if err.is_some() && err != events.restriction_error {
        eprintln!(
            "robodr-firewall-gw: WARNING: restriction file ignored: {}",
            err.as_deref().unwrap_or("")
        );
    }
    events.restriction_error = err;
    gw.discovery_mut().expire(Instant::now());
    if let Some(w) = gw.discovery().port_bypass().map(|w| w.to_string()) {
        if !events.port_warned {
            gw.findings
                .note(crate::findings::rules::PORT_BYPASS_RISK, None, || {
                    crate::findings::Detail {
                        what: Some(w),
                        ..crate::findings::Detail::reason("unqueued_locator")
                    }
                });
        }
    }
    let mode = match gw.mode() {
        GatewayMode::Enforce => robodr_events::Mode::Enforce,
        GatewayMode::Observe => robodr_events::Mode::Observe,
    };
    let mut out: Vec<(robodr_events::Deviation, Option<String>, u64)> = gw
        .firewall_mut()
        .drain_deviations()
        .into_iter()
        .map(|d| (d, None, 1))
        .collect();
    out.extend(
        gw.drain_webrtc()
            .into_iter()
            .map(|d| (d.with_mode(mode), Some("webrtc".to_string()), 1)),
    );
    out.extend(
        gw.findings
            .drain(mode)
            .into_iter()
            .map(|g| (g.deviation, g.channel, g.count)),
    );
    for (d, channel, count) in &out {
        if let Some(feed) = events.feed.as_mut() {
            if let Some(l) = crate::feed::line(d, channel.as_deref(), *count) {
                feed.push(l);
            }
        }
        let Some(f) = events.file.as_mut() else {
            continue;
        };
        let Ok(line) = serde_json::to_string(d) else {
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
    if let Some(w) = gw.discovery().port_bypass() {
        if !events.port_warned {
            events.port_warned = true;
            eprintln!(
                "robodr-firewall-gw: WARNING: {w}: RTPS to that port bypasses the gateway; \
                 add it to rtps.extra_port_ranges (and regenerate the ruleset) or fix the DDS \
                 port configuration (status flag port_bypass_risk)"
            );
        }
    }
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
            "port_bypass_risk": gw.discovery().port_bypass().is_some(),
            "port_bypass": gw.discovery().port_bypass(),
            "queued_rtps_port_ranges": cfg.rtps_port_ranges(),
            "observe_enabled": cfg.observe.enabled,
            "observe_unavailable": events.observe_unavailable,
            "observe_overruns": events.observe_overruns,
            "observer": gw.observer().stats,
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
            "restriction": gw.restriction().map(|r| json!({
                "id": r.id, "max_linear_speed": r.max_linear_speed,
                "max_joint_speed": r.max_joint_speed, "factor": r.factor,
                "expires_unix_ms": r.expires_unix_ms,
            })),
            "restriction_error": events.restriction_error,
            "findings_total": gw.findings.total,
            "findings_feed": events.feed.as_ref().map(|f| {
                let s = f.status();
                json!({
                    "connected": s.connected, "sent": s.sent, "pending": s.pending,
                    "dropped": s.dropped, "last_error": s.last_error,
                })
            }),
        });
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, status.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}
