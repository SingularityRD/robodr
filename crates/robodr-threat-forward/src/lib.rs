//! `robodr-threat-forward`: a Pulsar module that hands every Pulsar threat to
//! `robodr-agentd`, so the host-dependent correlation rules can fire there.
//!
//! **Pulsar-dependent crate** (`pulsar-core`); only `robodr-pulsard`
//! depends on it.
//!
//! ```text
//!  Pulsar bus ──► on_event (threat?) ──► try_send ──► bounded queue ──► writer thread
//!   (rules-engine,      │                    │ full: dropped++          │ UnixStream, line framing
//!    other modules)     │ own sensor: skip   │                          │ reconnect with backoff
//!                       ▼                    ▼                          ▼
//!                  skipped_own++        never blocks           agentd host_threats socket
//! ```
//!
//! # What is forwarded
//!
//! Every bus event that carries a threat (`header.threat`), like Pulsar's
//! own `threat-logger`, **except** threats raised by `robodr-sensor-ros2`:
//! agentd already sees those findings through its own pipeline, and
//! forwarding them would count them twice. One JSON object per line:
//!
//! ```json
//! {"kind":"threat","v":1,"rule":"RoboDR: Interactive shell started on robot controller",
//!  "source":"rules-engine","severity":"medium","category":"execution",
//!  "ts_ms":1790000000000,"pid":4242,"ppid":1,"uid":0,"gid":0,"image":"/usr/bin/bash",
//!  "container":false}
//! {"kind":"heartbeat","v":1,"sent":17,"dropped":0,"skipped_own":3}
//! ```
//!
//! * `rule` is the threat's description as Pulsar gives it. For the
//!   rules-engine this is the rule `name` (`rules/robodr/*.toml`), which is
//!   exactly the host rule id the correlation rules match.
//! * `severity` / `category` come from the rules-engine's `extra` metadata
//!   when present (`low` / `medium` / `high` / `critical`); otherwise absent.
//! * Strings are bounded ([`MAX_RULE_BYTES`], [`MAX_IMAGE_BYTES`], ...) and
//!   control characters are replaced by `?`: `image` is the exec path of an
//!   arbitrary local process and may be hostile.
//! * A heartbeat is written right after every connect and whenever nothing
//!   was written for `heartbeat_ms`, with the module's cumulative counters.
//!   agentd counts it as liveness: a configured host input whose forwarder is
//!   gone goes *silent* there, and the daemon then reports `unknown`, never
//!   `ok`.
//!
//! # Never stalls the bus
//!
//! `on_event` only serialises the line and `try_send`s it into a bounded
//! queue (`queue_capacity`, default 1024). A full queue drops the threat and
//! counts it (`dropped`, reported in the next heartbeat). A dedicated OS
//! thread owns the socket: it connects, writes with a write timeout, and on
//! any error drops the connection and reconnects with exponential backoff
//! (100 ms to 5 s). While agentd is not there, threats wait in the queue (up
//! to its capacity) and are delivered after the reconnect. A line whose
//! write failed is counted as dropped, never retried (a partial line may
//! have reached the peer).

// S10 (review I3): no `unsafe` code here (checked with grep; the only
// macros used, `tokio::main` / `tokio::select!` and derives, compile under
// `forbid(unsafe_code)`), and it must stay that way.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use pulsar_core::pdk::{Event, ModuleContext, ModuleError, SimplePulsarModule};
use serde::{Deserialize, Serialize};

/// Module name, i.e. the `[module.<name>]` section in `pulsar.toml`.
pub const MODULE_NAME: &str = "robodr-threat-forward";
/// Threats from this module are not forwarded (agentd has its own pipeline).
pub const SENSOR_MODULE: &str = "robodr-sensor-ros2";
/// Line protocol version (`"v"`).
pub const PROTOCOL_VERSION: u32 = 1;
/// Bound of `rule` (bytes). Also the correlation engine's entity bound.
pub const MAX_RULE_BYTES: usize = 256;
/// Bound of `image` (bytes).
pub const MAX_IMAGE_BYTES: usize = 256;
/// Bound of `source` (bytes).
pub const MAX_SOURCE_BYTES: usize = 64;
/// Bound of `category` (bytes).
pub const MAX_CATEGORY_BYTES: usize = 64;
/// agentd refuses longer lines (`robodr_agentd::host::MAX_HOST_LINE_BYTES`).
pub const MAX_LINE_BYTES: usize = 4096;
/// Bounds of `queue_capacity`.
pub const MAX_QUEUE_CAPACITY: usize = 65_536;
/// First and largest reconnect delay.
pub const MIN_BACKOFF: Duration = Duration::from_millis(100);
pub const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// Longest sleep of the writer while disconnected (stop latency).
const IDLE_POLL: Duration = Duration::from_millis(100);

/// `[module.robodr-threat-forward]`.
///
/// ```toml
/// [module.robodr-threat-forward]
/// enabled = true
/// socket_path = "/run/robodr-agentd/host-threats.sock"
/// # queue_capacity = 1024
/// # heartbeat_ms = 5000      # must stay well below agentd's daemon.silence_ms
/// # write_timeout_ms = 1000
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// agentd's `host_threats.socket_path` (absolute). Required.
    pub socket_path: Option<PathBuf>,
    /// Threats queued while the writer is busy or agentd is away.
    pub queue_capacity: usize,
    /// Heartbeat period when nothing else was written.
    pub heartbeat_ms: u64,
    /// A write blocked longer than this drops the connection.
    pub write_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: None,
            queue_capacity: 1024,
            heartbeat_ms: 5000,
            write_timeout_ms: 1000,
        }
    }
}

/// A validated [`Config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub socket_path: PathBuf,
    pub queue_capacity: usize,
    pub heartbeat: Duration,
    pub write_timeout: Duration,
}

impl Config {
    pub fn validate(&self) -> Result<Settings, String> {
        let Some(p) = &self.socket_path else {
            return Err(format!(
                "[module.{MODULE_NAME}] socket_path is required (agentd's host_threats.socket_path)"
            ));
        };
        if !p.is_absolute() {
            return Err(format!(
                "[module.{MODULE_NAME}] socket_path must be absolute, got {:?}",
                bounded(&p.display().to_string(), MAX_IMAGE_BYTES)
            ));
        }
        if !(1..=MAX_QUEUE_CAPACITY).contains(&self.queue_capacity) {
            return Err(format!(
                "[module.{MODULE_NAME}] queue_capacity must be 1..={MAX_QUEUE_CAPACITY}"
            ));
        }
        if !(100..=60_000).contains(&self.heartbeat_ms) {
            return Err(format!(
                "[module.{MODULE_NAME}] heartbeat_ms must be 100..=60000"
            ));
        }
        if !(10..=60_000).contains(&self.write_timeout_ms) {
            return Err(format!(
                "[module.{MODULE_NAME}] write_timeout_ms must be 10..=60000"
            ));
        }
        Ok(Settings {
            socket_path: p.clone(),
            queue_capacity: self.queue_capacity,
            heartbeat: Duration::from_millis(self.heartbeat_ms),
            write_timeout: Duration::from_millis(self.write_timeout_ms),
        })
    }
}

/// One forwarded threat (see the crate docs for the field meanings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub v: u32,
    pub rule: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Wall-clock time of the event (Unix ms).
    pub ts_ms: u64,
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    pub image: String,
    /// The process runs in a container.
    pub container: bool,
}

/// Liveness line with the module's cumulative counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub v: u32,
    pub sent: u64,
    pub dropped: u64,
    pub skipped_own: u64,
}

/// One line of the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Line {
    Threat(ThreatRecord),
    Heartbeat(Heartbeat),
}

impl Line {
    /// The JSON line without its newline.
    pub fn to_json(&self) -> String {
        // Plain structs of strings and integers: serialisation cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// `s` with control characters replaced by `?`, cut to at most `max` bytes
/// on a character boundary.
pub fn bounded(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars() {
        let c = if c.is_control() { '?' } else { c };
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];

/// The record for `event`, if it is a threat.
pub fn record_from_event(event: &Event) -> Option<ThreatRecord> {
    let h = event.header();
    let threat = h.threat.as_ref()?;
    let extra = threat
        .extra
        .as_ref()
        .and_then(|v| serde_json::to_value(v).ok());
    let field = |k: &str| {
        extra
            .as_ref()
            .and_then(|e| e.get(k))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let severity = field("severity")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| SEVERITIES.contains(&s.as_str()));
    let category = field("category").map(|c| bounded(&c, MAX_CATEGORY_BYTES));
    let ts_ms = h
        .timestamp
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    Some(ThreatRecord {
        v: PROTOCOL_VERSION,
        rule: bounded(&threat.description, MAX_RULE_BYTES),
        source: bounded(&threat.source, MAX_SOURCE_BYTES),
        severity,
        category,
        ts_ms,
        pid: h.pid,
        ppid: h.parent_pid,
        uid: h.uid,
        gid: h.gid,
        image: bounded(&h.image, MAX_IMAGE_BYTES),
        container: h.container.is_some(),
    })
}

/// Counters shared by the module and its writer thread.
#[derive(Debug, Default)]
pub struct Counters {
    /// Threats accepted into the queue.
    pub queued: AtomicU64,
    /// Threats written to agentd.
    pub sent: AtomicU64,
    /// Threats lost: queue full, writer gone, or the write failed.
    pub dropped: AtomicU64,
    /// Threats of `robodr-sensor-ros2`, not forwarded.
    pub skipped_own: AtomicU64,
    /// Successful connects.
    pub connects: AtomicU64,
    /// Heartbeats written.
    pub heartbeats: AtomicU64,
    /// A connection to agentd is open.
    pub connected: AtomicBool,
}

impl Counters {
    fn heartbeat(&self) -> Heartbeat {
        Heartbeat {
            v: PROTOCOL_VERSION,
            sent: self.sent.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            skipped_own: self.skipped_own.load(Ordering::Relaxed),
        }
    }

    fn drop_one(&self) {
        let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            log::warn!(target: MODULE_NAME, "{n} threat(s) not forwarded to agentd so far");
        }
    }
}

/// What [`Forwarder::offer`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Queued,
    /// From `robodr-sensor-ros2`: agentd already has it.
    SkippedOwn,
    /// Queue full or writer gone; counted in [`Counters::dropped`].
    Dropped,
}

/// The bounded queue and its writer thread. Dropping it stops the thread
/// (within one poll or write timeout; it is not joined).
pub struct Forwarder {
    tx: Option<SyncSender<String>>,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

impl Forwarder {
    pub fn spawn(settings: Settings) -> io::Result<Self> {
        let (tx, rx) = sync_channel::<String>(settings.queue_capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let (s2, c2) = (stop.clone(), counters.clone());
        std::thread::Builder::new()
            .name("robodr-threat-fwd".into())
            .spawn(move || writer_loop(&settings, &rx, &s2, &c2))?;
        Ok(Self {
            tx: Some(tx),
            stop,
            counters,
        })
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Queue `rec` without blocking.
    pub fn offer(&self, rec: ThreatRecord) -> Offer {
        if rec.source == SENSOR_MODULE {
            self.counters.skipped_own.fetch_add(1, Ordering::Relaxed);
            return Offer::SkippedOwn;
        }
        let line = Line::Threat(rec).to_json();
        let Some(tx) = &self.tx else {
            self.counters.drop_one();
            return Offer::Dropped;
        };
        match tx.try_send(line) {
            Ok(()) => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
                Offer::Queued
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.counters.drop_one();
                Offer::Dropped
            }
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Disconnects the queue: a writer waiting in recv returns at once.
        self.tx.take();
    }
}

fn write_line(conn: &mut UnixStream, line: &str) -> io::Result<()> {
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    conn.write_all(&buf)
}

fn connect(s: &Settings) -> io::Result<UnixStream> {
    let c = UnixStream::connect(&s.socket_path)?;
    c.set_write_timeout(Some(s.write_timeout))?;
    Ok(c)
}

fn writer_loop(s: &Settings, rx: &Receiver<String>, stop: &AtomicBool, c: &Counters) {
    let mut conn: Option<UnixStream> = None;
    let mut backoff = MIN_BACKOFF;
    let mut next_attempt = Instant::now();
    let mut last_write = Instant::now();
    let mut warned = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Some(stream) = conn.as_mut() else {
            if Instant::now() >= next_attempt {
                match connect(s) {
                    Ok(mut st) => {
                        // Liveness first: agentd stops reporting the input
                        // as "no data yet" at once.
                        let hb = Line::Heartbeat(c.heartbeat()).to_json();
                        if write_line(&mut st, &hb).is_ok() {
                            c.heartbeats.fetch_add(1, Ordering::Relaxed);
                            c.connects.fetch_add(1, Ordering::Relaxed);
                            c.connected.store(true, Ordering::SeqCst);
                            log::info!(
                                target: MODULE_NAME,
                                "connected to agentd at {}",
                                s.socket_path.display()
                            );
                            warned = false;
                            backoff = MIN_BACKOFF;
                            last_write = Instant::now();
                            conn = Some(st);
                            continue;
                        }
                    }
                    Err(e) => {
                        if !warned {
                            warned = true;
                            log::warn!(
                                target: MODULE_NAME,
                                "agentd host-threat socket {} not reachable ({e}); \
                                 retrying, threats are queued",
                                s.socket_path.display()
                            );
                        }
                    }
                }
                next_attempt = Instant::now() + backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            let wait = next_attempt
                .saturating_duration_since(Instant::now())
                .min(IDLE_POLL);
            std::thread::sleep(wait);
            continue;
        };
        let wait = s.heartbeat.saturating_sub(last_write.elapsed());
        let (line, threat) = match rx.recv_timeout(wait) {
            Ok(l) => (l, true),
            Err(RecvTimeoutError::Timeout) => (Line::Heartbeat(c.heartbeat()).to_json(), false),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        match write_line(stream, &line) {
            Ok(()) => {
                last_write = Instant::now();
                if threat {
                    c.sent.fetch_add(1, Ordering::Relaxed);
                } else {
                    c.heartbeats.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                if threat {
                    c.drop_one();
                }
                c.connected.store(false, Ordering::SeqCst);
                log::warn!(
                    target: MODULE_NAME,
                    "lost the agentd connection ({e}); reconnecting"
                );
                conn = None;
                next_attempt = Instant::now() + backoff;
            }
        }
    }
}

/// The Pulsar module. Register it with
/// `PulsarDaemonStarter::add_module(ThreatForwarder)` (see `robodr-pulsard`).
pub struct ThreatForwarder;

/// Running state: the forwarder (its writer thread stops when this drops,
/// also when Pulsar drops the state without `graceful_stop`).
pub struct State {
    forwarder: Forwarder,
}

impl SimplePulsarModule for ThreatForwarder {
    type Config = Config;
    type State = State;

    const MODULE_NAME: &'static str = MODULE_NAME;
    const DEFAULT_ENABLED: bool = false;

    async fn init_state(
        &self,
        config: &Self::Config,
        _ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        let settings = config.validate()?;
        log::info!(
            target: MODULE_NAME,
            "forwarding Pulsar threats to {} (queue {}, heartbeat {} ms)",
            settings.socket_path.display(),
            settings.queue_capacity,
            settings.heartbeat.as_millis()
        );
        let forwarder =
            Forwarder::spawn(settings).map_err(|e| format!("starting the writer thread: {e}"))?;
        Ok(State { forwarder })
    }

    async fn on_event(
        event: &Event,
        _config: &Self::Config,
        state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        if let Some(rec) = record_from_event(event) {
            state.forwarder.offer(rec);
        }
        Ok(())
    }

    async fn graceful_stop(state: Self::State) -> Result<(), ModuleError> {
        drop(state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    fn tmp(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-threat-fwd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn settings(path: PathBuf, cap: usize, hb_ms: u64) -> Settings {
        Config {
            socket_path: Some(path),
            queue_capacity: cap,
            heartbeat_ms: hb_ms,
            write_timeout_ms: 500,
        }
        .validate()
        .unwrap()
    }

    fn rec(rule: &str, source: &str) -> ThreatRecord {
        ThreatRecord {
            v: PROTOCOL_VERSION,
            rule: rule.into(),
            source: source.into(),
            severity: Some("high".into()),
            category: None,
            ts_ms: 1,
            pid: 42,
            ppid: 1,
            uid: 0,
            gid: 0,
            image: "/usr/bin/bash".into(),
            container: false,
        }
    }

    /// A pulsar-core threat event, built from its serde form.
    fn event(description: &str, source: &str, image: &str, extra: serde_json::Value) -> Event {
        let j = serde_json::json!({
            "header": {
                "image": image, "pid": 4242, "parent_pid": 1, "uid": 1000, "gid": 1000,
                "container": null,
                "threat": {"source": source, "description": description, "extra": extra},
                "source": source,
                "timestamp": {"secs_since_epoch": 1_790_000_000u64, "nanos_since_epoch": 5_000_000},
                "fork_time": {"secs_since_epoch": 1_790_000_000u64, "nanos_since_epoch": 0},
            },
            "payload": {"type": "Empty"},
        });
        serde_json::from_value(j).unwrap()
    }

    #[test]
    fn rules_engine_threat_becomes_a_bounded_record() {
        let ev = event(
            "RoboDR: Interactive shell started on robot controller",
            "rules-engine",
            "/usr/bin/bash",
            serde_json::json!({"category": "execution", "severity": "medium",
                               "description": "d", "condition": "c"}),
        );
        let r = record_from_event(&ev).unwrap();
        assert_eq!(
            r.rule,
            "RoboDR: Interactive shell started on robot controller"
        );
        assert_eq!(r.source, "rules-engine");
        assert_eq!(r.severity.as_deref(), Some("medium"));
        assert_eq!(r.category.as_deref(), Some("execution"));
        assert_eq!(r.ts_ms, 1_790_000_000_005);
        assert_eq!((r.pid, r.ppid, r.uid, r.gid), (4242, 1, 1000, 1000));
        assert!(!r.container);
        let line = Line::Threat(r.clone()).to_json();
        assert!(line.starts_with("{\"kind\":\"threat\",\"v\":1,"), "{line}");
        assert_eq!(
            serde_json::from_str::<Line>(&line).unwrap(),
            Line::Threat(r)
        );

        // Hostile image: control characters replaced, length bounded.
        let evil = format!("/tmp/\u{1b}[31m\n{}", "é".repeat(400));
        let ev = event("x", "other-module", &evil, serde_json::Value::Null);
        let r = record_from_event(&ev).unwrap();
        assert!(r.image.len() <= MAX_IMAGE_BYTES);
        assert!(!r.image.chars().any(char::is_control), "{:?}", r.image);
        assert_eq!(r.severity, None);
        assert!(Line::Threat(r).to_json().len() < MAX_LINE_BYTES);

        // Unknown severity values are dropped, not passed through.
        let ev = event(
            "x",
            "m",
            "/x",
            serde_json::json!({"severity": "catastrophic"}),
        );
        assert_eq!(record_from_event(&ev).unwrap().severity, None);
    }

    #[test]
    fn worst_case_line_fits_agentds_limit() {
        let big = "\u{10FFFF}".repeat(1000);
        let r = ThreatRecord {
            v: PROTOCOL_VERSION,
            rule: bounded(&big, MAX_RULE_BYTES),
            source: bounded(&big, MAX_SOURCE_BYTES),
            severity: Some("critical".into()),
            category: Some(bounded(&big, MAX_CATEGORY_BYTES)),
            ts_ms: u64::MAX,
            pid: i32::MIN,
            ppid: i32::MIN,
            uid: u32::MAX,
            gid: u32::MAX,
            image: bounded(&big, MAX_IMAGE_BYTES),
            container: true,
        };
        let line = Line::Threat(r).to_json();
        assert!(line.len() < MAX_LINE_BYTES, "{}", line.len());
    }

    /// Everything the forwarder writes is accepted by agentd's strict
    /// parser, with the same values; the bounds agree.
    #[test]
    fn agentd_accepts_every_line_the_forwarder_writes() {
        use robodr_agentd::host::{self as agentd, HostLine};
        assert_eq!(MAX_LINE_BYTES, agentd::MAX_HOST_LINE_BYTES);
        assert_eq!(MAX_RULE_BYTES, agentd::MAX_RULE_BYTES);
        assert_eq!(MAX_IMAGE_BYTES, agentd::MAX_IMAGE_BYTES);
        assert_eq!(MAX_SOURCE_BYTES, agentd::MAX_SOURCE_BYTES);
        assert_eq!(MAX_CATEGORY_BYTES, agentd::MAX_CATEGORY_BYTES);
        assert_eq!(PROTOCOL_VERSION, agentd::HOST_PROTOCOL_VERSION);
        assert_eq!(SENSOR_MODULE, agentd::SENSOR_MODULE);
        let hostile = format!("/tmp/\u{1b}]0;x\u{7}\n{}", "\u{10FFFF}".repeat(200));
        let ev = event(
            &format!("RoboDR: Interactive shell\r\n{hostile}"),
            "rules-engine",
            &hostile,
            serde_json::json!({"category": "exec\u{0}ution", "severity": "HIGH"}),
        );
        let r = record_from_event(&ev).unwrap();
        let line = Line::Threat(r.clone()).to_json();
        match agentd::parse_host(&line).unwrap_or_else(|e| panic!("{line}: {e}")) {
            HostLine::Threat(t) => {
                assert_eq!(t.rule, r.rule);
                assert_eq!(t.image, r.image);
                assert_eq!(t.pid, 4242);
                assert_eq!(t.severity, Some(robodr_agentd::host::Severity::High));
                assert_eq!(t.category, r.category);
            }
            other => panic!("{other:?}"),
        }
        let hb = Line::Heartbeat(Heartbeat {
            v: PROTOCOL_VERSION,
            sent: 1,
            dropped: 2,
            skipped_own: 3,
        })
        .to_json();
        assert!(matches!(
            agentd::parse_host(&hb).unwrap(),
            HostLine::Heartbeat(h) if (h.sent, h.dropped, h.skipped_own) == (1, 2, 3)
        ));
    }

    #[test]
    fn config_validation() {
        assert!(
            Config::default().validate().is_err(),
            "socket_path required"
        );
        let rel = Config {
            socket_path: Some("rel.sock".into()),
            ..Config::default()
        };
        assert!(rel.validate().is_err());
        let ok = Config {
            socket_path: Some("/run/x.sock".into()),
            ..Config::default()
        };
        assert_eq!(ok.validate().unwrap().queue_capacity, 1024);
        let zero = Config {
            queue_capacity: 0,
            ..ok.clone()
        };
        assert!(zero.validate().is_err());
        let hb = Config {
            heartbeat_ms: 10,
            ..ok
        };
        assert!(hb.validate().is_err());
    }

    fn read_line(r: &mut BufReader<UnixStream>) -> Line {
        let mut s = String::new();
        r.read_line(&mut s).unwrap();
        serde_json::from_str(s.trim_end()).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    #[test]
    fn forwards_lines_heartbeats_and_skips_own_sensor() {
        let dir = tmp("fwd");
        let path = dir.join("h.sock");
        let l = UnixListener::bind(&path).unwrap();
        let f = Forwarder::spawn(settings(path, 16, 150)).unwrap();
        let (conn, _) = l.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut r = BufReader::new(conn);
        // Hello heartbeat first.
        assert!(matches!(read_line(&mut r), Line::Heartbeat(h) if h.sent == 0));
        assert_eq!(f.offer(rec("RoboDR: a", "rules-engine")), Offer::Queued);
        assert_eq!(f.offer(rec("own", SENSOR_MODULE)), Offer::SkippedOwn);
        assert_eq!(f.offer(rec("RoboDR: b", "rules-engine")), Offer::Queued);
        match read_line(&mut r) {
            Line::Threat(t) => assert_eq!(t.rule, "RoboDR: a"),
            other => panic!("{other:?}"),
        }
        match read_line(&mut r) {
            Line::Threat(t) => assert_eq!(t.rule, "RoboDR: b"),
            other => panic!("{other:?}"),
        }
        // Idle: a heartbeat with the counters.
        match read_line(&mut r) {
            Line::Heartbeat(h) => {
                assert_eq!((h.sent, h.dropped, h.skipped_own), (2, 0, 1));
            }
            other => panic!("{other:?}"),
        }
        assert!(f.counters().connected.load(Ordering::SeqCst));
        drop(f);
        // The writer stops: the peer sees EOF.
        let mut rest = String::new();
        let n = r.read_line(&mut rest).unwrap_or(0);
        assert!(n == 0 || rest.contains("heartbeat"), "{rest:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queues_while_agentd_is_away_drops_when_full_and_reconnects() {
        let dir = tmp("away");
        let path = dir.join("h.sock");
        let f = Forwarder::spawn(settings(path.clone(), 2, 5000)).unwrap();
        // Nobody listens: the queue (capacity 2) fills, the rest is dropped.
        let offers: Vec<Offer> = (0..5)
            .map(|i| f.offer(rec(&format!("RoboDR: {i}"), "rules-engine")))
            .collect();
        assert_eq!(offers.iter().filter(|o| **o == Offer::Queued).count(), 2);
        assert_eq!(f.counters().dropped.load(Ordering::Relaxed), 3);
        // agentd appears: the queued threats arrive after the hello.
        let l = UnixListener::bind(&path).unwrap();
        let (conn, _) = l.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut r = BufReader::new(conn);
        match read_line(&mut r) {
            Line::Heartbeat(h) => assert_eq!(h.dropped, 3),
            other => panic!("{other:?}"),
        }
        for want in ["RoboDR: 0", "RoboDR: 1"] {
            match read_line(&mut r) {
                Line::Threat(t) => assert_eq!(t.rule, want),
                other => panic!("{other:?}"),
            }
        }
        // agentd restarts: the forwarder reconnects by itself.
        drop(r);
        drop(l);
        std::fs::remove_file(&path).unwrap();
        let l = UnixListener::bind(&path).unwrap();
        // The next write to the closed connection fails (EPIPE, counted as
        // dropped) and makes the writer reconnect.
        f.offer(rec("RoboDR: lost", "rules-engine"));
        let (conn, _) = l.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut r = BufReader::new(conn);
        assert!(matches!(read_line(&mut r), Line::Heartbeat(_)));
        assert_eq!(f.offer(rec("RoboDR: again", "rules-engine")), Offer::Queued);
        match read_line(&mut r) {
            Line::Threat(t) => assert_eq!(t.rule, "RoboDR: again"),
            other => panic!("{other:?}"),
        }
        assert!(f.counters().connects.load(Ordering::Relaxed) >= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offer_never_blocks_on_a_stalled_peer() {
        let dir = tmp("stall");
        let path = dir.join("h.sock");
        let l = UnixListener::bind(&path).unwrap();
        let f = Forwarder::spawn(settings(path, 8, 5000)).unwrap();
        let (_conn, _) = l.accept().unwrap();
        // The peer never reads; the socket buffer fills, the writer times
        // out, the queue fills: offer still returns at once.
        let start = Instant::now();
        let big = "x".repeat(MAX_RULE_BYTES);
        for _ in 0..20_000 {
            f.offer(rec(&big, "rules-engine"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        assert!(f.counters().dropped.load(Ordering::Relaxed) > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
